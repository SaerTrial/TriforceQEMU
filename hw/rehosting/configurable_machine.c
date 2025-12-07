#include "qemu/osdep.h"
#include "qapi/error.h"

#include "hw/boards.h"
#include "qemu/error-report.h"
#include "exec/address-spaces.h"
#include "net/net.h"
#include "hw/char/serial.h"
#include "sysemu/qtest.h"
#include "sysemu/sysemu.h"
#include "qemu/cutils.h"
#include "hw/qdev-clock.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qnum.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qnull.h"
#include "qapi/qmp/qstring.h"
#include "qapi/qmp/qjson.h"
#include "qemu/log.h"
#include "hw/rehosting/utils/mem.h"

#ifdef TARGET_ARM
#include "hw/arm/boot.h"
#include "hw/arm/armv7m.h"
#include "target/arm/cpu.h"
#include "hw/rehosting/arm/function_hooks.h"
typedef ARMCPU THISCPU;
#endif

#include "patches/afl.h"

#define SYSCLK_FRQ 40000000ULL

#define QDICT_ASSERT_KEY_TYPE(_dict, _key, _type) \
    g_assert(qdict_haskey(_dict, _key) && qobject_type(qdict_get(_dict, _key)) == _type)
#define DEBUG


extern const char *replayConf;
GHashTable *patched_func_htable = NULL;
GHashTable *exit_at_htable = NULL;


static QDict * load_configuration(const char * filename) {
    int file = open(filename, O_RDONLY);
    off_t filesize = lseek(file, 0, SEEK_END);
    char * filedata = NULL;
    ssize_t err;
    QObject * obj;

    lseek(file, 0, SEEK_SET);

    filedata = g_malloc(filesize + 1);
    memset(filedata, 0, filesize + 1);

    if (!filedata)
    {
        fprintf(stderr, "%ld\n", filesize);
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    err = read(file, filedata, filesize);

    if (err != filesize)
    {
        fprintf(stderr, "Reading configuration file failed\n");
        exit(1);
    }

    close(file);

    obj = qobject_from_json(filedata, NULL);
    if (!obj || qobject_type(obj) != QTYPE_QDICT)
    {
        fprintf(stderr, "Error parsing JSON configuration file\n");
        exit(1);
    }

    g_free(filedata);

    return qobject_to(QDict, obj);
}

uint32_t mmio_start, mmio_end;

static void load_ram(QDict * ram_dict) {
        Error *err = NULL;
        MemoryRegion *system_memory = get_system_memory();
        MemoryRegion *ram = g_new(MemoryRegion, 1);
        const char* ram_name = qstring_get_str(qobject_to(QString, qdict_get(ram_dict, "name")));
        uint32_t ram_addr = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(ram_dict, "addr"))),
                NULL,
                0);
        
        uint32_t ram_size = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(ram_dict, "size"))),
                NULL,
                0);

        memory_region_init_ram(ram, NULL, ram_name, 
                                ram_size, &err);
        memory_region_add_subregion(system_memory, ram_addr, ram);


        if (ram_ranges == NULL) ram_ranges = g_ptr_array_new_with_free_func(g_free);

        MemRange *r = g_new0(MemRange, 1);
        r->start = ram_addr;
        r->end   = ram_addr + ram_size;
        g_ptr_array_add(ram_ranges, r);

}

/* borrow from avatar-qemu */

static off_t get_file_size(const char * path) {
    struct stat stats;

    if (stat(path, &stats)) {
        printf("ERROR: Getting file size for file %s\n", path);
        return 0;
    }

    return stats.st_size;
}

static int is_absolute_path(const char * filename) {
    return filename[0] == '/';
}

static int get_dirname_len(const char * filename) {
    int i;

    for (i = strlen(filename) - 1; i >= 0; i--) {
        //FIXME: This is only Linux-compatible ...
        if (filename[i] == '/') {
            return i + 1;
        }
    }

    return 0;
}

uint32_t flash_addr;
uint32_t flash_size;
const char* kernel_filename;

static void load_flash(QDict * flash_dict) {
        MemoryRegion *system_memory = get_system_memory();        
        Error *err = NULL;
        char* data = NULL;
        uint32_t data_size;

        flash_addr = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(flash_dict, "addr"))),
                NULL,
                0);
        
        flash_size = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(flash_dict, "size"))),
                NULL,
                0);

        const char* flash_name = qstring_get_str(qobject_to(QString, qdict_get(flash_dict, "name")));

        MemoryRegion *flash =  g_new(MemoryRegion, 1);

        memory_region_init_rom(flash, NULL, flash_name,
                                flash_size, &err);

        // TODO: check if a overlapping region has been previously allocated
        memory_region_add_subregion(system_memory, flash_addr, flash);

        uint32_t alias_addr = 0xffffffff;
        if (qdict_haskey(flash_dict, "alias_at")) {
                MemoryRegion *flash_alias =  g_new(MemoryRegion, 1);

                alias_addr = strtol( 
                        qstring_get_str(qobject_to(QString, qdict_get(flash_dict, "alias_at"))),
                        NULL,
                        0);

                char* alias_name = g_malloc(strlen(flash_name)+1+strlen(".alias"));
                
                sprintf(alias_name, "%s.alias", flash_name);

                memory_region_init_alias(flash_alias, NULL,
                        alias_name, flash, 0,
                        flash_size);
        
                memory_region_add_subregion(system_memory, alias_addr, flash_alias);
        }


        /* borrow from avatar-qemu */
        if (qdict_haskey(flash_dict, "file"))
        {
                int file;
                const char * filename;
                int dirname_len = get_dirname_len(kernel_filename);
                ssize_t err_file;
                uint32_t file_offset = 0;

                g_assert(qobject_type(qdict_get(flash_dict, "file")) == QTYPE_QSTRING);
                filename = qdict_get_str(flash_dict, "file");

                if (!is_absolute_path(filename)) {
                char * relative_filename = g_malloc0(dirname_len +
                                                        strlen(filename) + 1);
                g_assert(relative_filename);
                strncpy(relative_filename, kernel_filename, dirname_len);
                strcat(relative_filename, filename);

                file = open(relative_filename, O_RDONLY | O_BINARY);
                data_size = get_file_size(relative_filename);
                g_free(relative_filename);
                }
                else {
                file = open(filename, O_RDONLY | O_BINARY);
                data_size = get_file_size(filename);
                }

                if (qdict_haskey(flash_dict, "file_offset")) {
                off_t sbytes;
                g_assert(qobject_type(qdict_get(flash_dict, "file_offset")) == QTYPE_QNUM);
                file_offset = qdict_get_int(flash_dict, "file_offset");
                sbytes = lseek(file,file_offset,SEEK_SET);
                g_assert(sbytes > 0);
                data_size -= sbytes;
                }

                if (qdict_haskey(flash_dict,"file_bytes")) {
                ssize_t file_bytes;
                g_assert(qobject_type(qdict_get(flash_dict, "file_bytes")) == QTYPE_QNUM);
                file_bytes = qdict_get_int(flash_dict, "file_bytes");
                data_size = file_bytes;
                printf("File bytes: 0x%x\n",data_size);

                }

                printf("Configurable: Inserting 0x%"
                PRIx32 " bytes of data in memory region %s\n", data_size, flash_name);
                //Size of data to put into a RAM region needs to fit in the RAM region
                g_assert(data_size <= flash_size);

                data = g_malloc(data_size);
                g_assert(data);

                err_file = read(file, data, data_size);
                g_assert(err_file == data_size);

                close(file);

                //And copy the data to the memory, if it is initialized
                printf("Configurable: Copying 0x%" PRIx32
                " byte of data from file %s beginning at offset 0x%" PRIx32
                " to address 0x%" PRIx32
                "\n", data_size, filename, file_offset, flash_addr);

                address_space_write_rom(&address_space_memory, flash_addr,
                                        MEMTXATTRS_UNSPECIFIED,
                                        (uint8_t *) data, data_size);
                g_free(data);
        }

        if (alias_addr == 0xffffffff)
                qemu_log_mask(LOG_AFL, "[%s] name: %s, addr: 0x%x, size: 0x%x \n", __func__, flash_name, flash_addr, flash_size);  
        else
                qemu_log_mask(LOG_AFL, "[%s] name: %s, alias: 0x%x, addr: 0x%x, size: 0x%x \n", __func__, flash_name, alias_addr, flash_addr, flash_size);  
}       

bool interrupt_firing_enabled = false;
uint32_t firing_frequency = 0x200;
uint8_t firing_mode = 0x0;
static void configure_interrupt_firing_strategy(QDict* interrupt_firing){
        assert(qdict_haskey(interrupt_firing, "mode") && "interrupt firing mode should be specified");
        interrupt_firing_enabled = true;
        
        if(!strcmp(qstring_get_str(qobject_to(QString, qdict_get(interrupt_firing, "mode"))), "round_robin")) 
                firing_mode = 0x1; // round robin mode
        else if (!strcmp(qstring_get_str(qobject_to(QString, qdict_get(interrupt_firing, "mode"))), "fuzzed"))
                firing_mode = 0x2; // fuzzed
        else if (!strcmp(qstring_get_str(qobject_to(QString, qdict_get(interrupt_firing, "mode"))), "specified"))
                firing_mode = 0x3;
        else 
                exit(-1);

        if (qdict_haskey(interrupt_firing, "frequency")) 
                firing_frequency = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(interrupt_firing, "frequency"))),
                NULL,
                0);

        qemu_log_mask(LOG_AFL, "[%s] firing mode: %d, firing frequency: 0x%x\n", __func__, firing_mode, firing_frequency);  
   
}


static void configure_mmio(QDict * mmio) {
        /*
        "mmio":[{"mmio_start":"0x40000000", "mmio_end": "0x60000000"},
               {"mmio_start":"0x70000000", "mmio_end": "0x80000000"}]
        */
        uint32_t mmio_start, mmio_end;

        QDICT_ASSERT_KEY_TYPE(mmio, "mmio_start", QTYPE_QSTRING);
        QDICT_ASSERT_KEY_TYPE(mmio, "mmio_end", QTYPE_QSTRING);

        mmio_start = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(mmio, "mmio_start"))),
                NULL,
                0);

        mmio_end = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(mmio, "mmio_end"))),
                NULL,
                0);
 
        if (mmio_ranges == NULL) mmio_ranges = g_ptr_array_new_with_free_func(g_free);

        MemRange *r = g_new0(MemRange, 1);
        r->start = mmio_start;
        r->end   = mmio_end;
        g_ptr_array_add(mmio_ranges, r);
}

static void create_patch(QDict * patch_entry){
    if (!patched_func_htable) patched_func_htable = g_hash_table_new(NULL, NULL);

    uint32_t addr = strtol(
                qstring_get_str(qobject_to(QString, qdict_get(patch_entry, "addr"))),
                NULL,
                0);
    
    void* element = NULL;
    if(! (element = g_hash_table_lookup(patched_func_htable, (gpointer)((uint64_t)addr)))) {
        if (qdict_haskey(patch_entry, "name"))
            element = (void*)qstring_get_str(qobject_to(QString, qdict_get(patch_entry, "name")));
        g_hash_table_insert(patched_func_htable, (gpointer)((uint64_t)addr), (gpointer)element);
    }
}

static void create_exit_at(QDict * exit_at_entry) {
        if (!exit_at_htable) exit_at_htable = g_hash_table_new(NULL, NULL);
        
        /*      
         "exit_at": [
         {"addr":"0x08000b20", "name":"Error_Handler"},
         {"addr":"0x080021c8", "name":"HardFault_Handler"}]
        */

        uint32_t addr = strtol(
                        qstring_get_str(qobject_to(QString, qdict_get(exit_at_entry, "addr"))),
                        NULL,
                        0);
        
        void* element = NULL;
        if(! (element = g_hash_table_lookup(exit_at_htable, (gpointer)((uint64_t)addr)))) {
                if (qdict_haskey(exit_at_entry, "name"))
                        element = (void*)qstring_get_str(qobject_to(QString, qdict_get(exit_at_entry, "name")));
                g_hash_table_insert(exit_at_htable, (gpointer)((uint64_t)addr), (gpointer)element);
        }
}

static void print_configuration(void){
        /* patch functions */
        GHashTableIter iter;
        uint32_t addr_iter;
        const char* func_name = NULL;
        g_hash_table_iter_init(&iter, patched_func_htable);
        uint32_t cnt = 0;

        qemu_log_mask(LOG_AFL,
        "[%s] --------------------------mmio range----------------------------\n", __func__);

        for (int i = 0; i < mmio_ranges->len; i++) {
                MemRange *r = g_ptr_array_index(mmio_ranges, i);
                qemu_log_mask(LOG_AFL,
                "%s: [%d] mmio_start: 0x%x mmio_end: 0x%x \n", __func__, cnt, r->start, r->end);
                cnt++;
        }

        cnt = 0;
        qemu_log_mask(LOG_AFL,
        "[%s] --------------------------ram range----------------------------\n", __func__);

        for (int i = 0; i < ram_ranges->len; i++) {
                MemRange *r = g_ptr_array_index(ram_ranges, i);
                qemu_log_mask(LOG_AFL,
                "%s: [%d] ram_start: 0x%x ram_end: 0x%x \n", __func__, cnt, r->start, r->end);
                cnt++;
        }

        cnt = 0;

        qemu_log_mask(LOG_AFL,
                "[%s] --------------------------patch function----------------------------\n", __func__);

        while (g_hash_table_iter_next(&iter, (gpointer)&addr_iter, (gpointer)&func_name)) {
                qemu_log_mask(LOG_AFL,
                "%s: [%d] addr: 0x%x patched_function: %s \n", __func__, cnt, addr_iter, func_name);
                cnt++;
        } 

        /* afl conf */
        qemu_log_mask(LOG_AFL,
                "[%s] --------------------------afl configuration----------------------------\n", __func__);
        qemu_log_mask(LOG_AFL,
                "%s: aflPanicAddr: 0x%lx aflDmesgAddr: 0x%lx \n", __func__, aflPanicAddr, aflDmesgAddr);
        

        cnt = 0;
        qemu_log_mask(LOG_AFL,
                "[%s] --------------------------exit_at function----------------------------\n", __func__);
                g_hash_table_iter_init(&iter, exit_at_htable);
        while (g_hash_table_iter_next(&iter, (gpointer)&addr_iter, (gpointer)&func_name)) {
                qemu_log_mask(LOG_AFL,
                "%s: [%d] exit_at addr: 0x%x (func_name): %s \n", __func__, cnt, addr_iter, func_name? func_name : "unknown");
                cnt++;
        } 


        qemu_log_mask(LOG_AFL,
                "[%s] will trigger a crash at 0x%x\n", __func__, (uint32_t)aflPanicAddr);

}

/* borrow from avatar-qemu */
static THISCPU *create_cpu(MachineState * ms, QDict *conf){
        const char *cpu_type;
        THISCPU *cpuu = NULL;
        // CPUState *env = NULL;

        const char *entry_field = "entry_address";
        uint32_t entrypoint;

        if(!qdict_haskey(conf, entry_field))
                exit(1);

        QDICT_ASSERT_KEY_TYPE(conf, entry_field, QTYPE_QSTRING);
        entrypoint = strtol(qdict_get_str(conf, entry_field), NULL, 0);


#if defined(TARGET_ARM)
        ObjectClass *cpu_oc;
#endif  /* TARGET_ARM || TARGET_I386 || TARGET_MIPS */

#if defined(TARGET_ARM) && !defined(TARGET_AARCH64)
        DeviceState *dstate; //generic device if CPU can be initiliazed via qdev-API
        int num_irq = 64;
#endif 

        char * cpu_type_string = NULL;

        if (qdict_haskey(conf, "cpu_model")) {
                cpu_type = qdict_get_str(conf, "cpu_model");
                g_assert(cpu_type);

                cpu_oc = cpu_class_by_name(TYPE_ARM_CPU, cpu_type);
                if (!cpu_oc) {
                        printf("Unable to find CPU definition\n");
                        exit(1);
                }

        #if defined(TARGET_ARM)
                cpu_type_string = g_malloc0(strlen(cpu_type) + strlen("-arm-cpu") + 1);
                sprintf(cpu_type_string, "%s-arm-cpu", cpu_type);
                cpu_type = cpu_type_string;
        #endif

        }else{
                cpu_type = ms->cpu_type;
        }


#if defined(TARGET_ARM) && !defined(TARGET_AARCH64)
        MemoryRegion *system_memory = get_system_memory();
        Clock *sysclk = NULL;
        
        if (qdict_haskey(conf, "num_irq")) {
                num_irq = qdict_get_int(conf, "num_irq");
                g_assert(num_irq);
        } 
        
        /* need a sysclk, otherwise realize would not succeed. The part connected to systick has been commented out */
        sysclk = clock_new(OBJECT(ms), "SYSCLK");
        clock_set_hz(sysclk, SYSCLK_FRQ);
        dstate = qdev_new(TYPE_ARMV7M);
        qdev_prop_set_uint32(dstate, "num-irq", num_irq);
        qdev_prop_set_uint8(dstate, "num-prio-bits", 4);
        qdev_prop_set_string(dstate, "cpu-type", cpu_type); //ARM_CPU_TYPE_NAME("cortex-m7")
        qdev_prop_set_bit(dstate, "enable-bitband", true);
        qdev_connect_clock_in(dstate, "cpuclk", sysclk);

        object_property_set_link(OBJECT(dstate), "memory",
                OBJECT(system_memory), &error_abort);

        if (!sysbus_realize_and_unref(SYS_BUS_DEVICE(dstate), NULL)) {
                exit(1);
        }
        
        cpuu = ARM_CPU(first_cpu);
        cpuu->env.regs[15] = entrypoint & (~1);
        afl_entry_point = cpuu->env.regs[15];
        cpuu->env.thumb = (entrypoint & 1) == 1 ? 1 : 0;


        assert(return_reg_index_by_name("r0") == 0 && return_reg_index_by_name("R0") == 0 && return_reg_index_by_name("XXX") == -1);
        
        if (qdict_haskey(conf, "init_state")) {
                QList *init_reg_entries = qobject_to(QList, qdict_get(conf, "init_state"));
                QListEntry *init_reg_entry;
                QLIST_FOREACH_ENTRY(init_reg_entries, init_reg_entry) {
                        QDict* init_reg_dict = qobject_to(QDict, qlist_entry_obj(init_reg_entry));
                        // get key and value
                        const QDictEntry * qdict_entry = qdict_first(init_reg_dict);

                        uint32_t reg_val = strtol(
                        qstring_get_str(qobject_to(QString, qdict_entry->value)),
                        NULL,
                        0);

                        int reg_idx = return_reg_index_by_name(qdict_entry->key);
                        
                        if ( reg_idx != -1) {
                                qemu_log_mask(LOG_AFL, "[%s] init reg(%s) with value(0x%x), idx: %d \n",
                                        __func__,
                                        qdict_entry->key, reg_val, 
                                        reg_idx);

                                cpuu->env.regs[reg_idx] = reg_val;
                        }
                }
        } 

#endif /* TARGET_ARM */

        return cpuu;     
}

static void machine_init(MachineState *machine)
{
        QDict * conf = NULL;

        assert (machine->kernel_filename != NULL && "a configuration file should be specified!");

        kernel_filename = machine->kernel_filename;

        conf = load_configuration(kernel_filename);

        if (covFile) {
                cov_fp = fopen(covFile, "w");
                assert (cov_fp && "create a cov file failed");
                fprintf(cov_fp, "EZCOV VERSION: 1\n");
        }

        assert(aflFile != NULL && "An input file should be provided!");

        if (qdict_haskey(conf, "aflPanicAddr")) {
                QDICT_ASSERT_KEY_TYPE(conf, "aflPanicAddr", QTYPE_QSTRING);
                aflPanicAddr = strtol(qdict_get_str(conf, "aflPanicAddr"), NULL, 0);
        }

        if (qdict_haskey(conf, "aflDmesgAddr")) {
                QDICT_ASSERT_KEY_TYPE(conf, "aflDmesgAddr", QTYPE_QSTRING);
                aflDmesgAddr = strtol(qdict_get_str(conf, "aflDmesgAddr"), NULL, 0);
        }
 
        const QDictEntry * entry = qdict_first(conf);
        while (entry) {
                if (!strcmp(entry->key, "ram")) {
                        QList * ram_entries = qobject_to(QList, entry->value);
                        QListEntry *ram_entry;
                        QLIST_FOREACH_ENTRY(ram_entries, ram_entry) {
                                load_ram(qobject_to(QDict, qlist_entry_obj(ram_entry)));
                        }
                }else if (!strcmp(entry->key, "flash")) {
                        QList * flash_entries = qobject_to(QList, entry->value);
                        QListEntry *flash_entry;
                        QLIST_FOREACH_ENTRY(flash_entries, flash_entry) {
                                load_flash(qobject_to(QDict, qlist_entry_obj(flash_entry)));
                        }
                }else if (!strcmp(entry->key, "mmio")) {
                        QList * mmio_entries = qobject_to(QList, entry->value);
                        QListEntry *mmio_entry;
                        QLIST_FOREACH_ENTRY(mmio_entries, mmio_entry) {
                                configure_mmio(qobject_to(QDict, qlist_entry_obj(mmio_entry)));
                        }
                }else if (!strcmp(entry->key, "patch")) {
                        QList * patch_entries = qobject_to(QList, entry->value);
                        QListEntry *patch_entry;
                        QLIST_FOREACH_ENTRY(patch_entries, patch_entry) {
                                create_patch(qobject_to(QDict, qlist_entry_obj(patch_entry)));
                        }
                }else if (!strcmp(entry->key, "exit_at")) {
                        QList * exit_entries = qobject_to(QList, entry->value);
                        QListEntry *exit_entry;
                        QLIST_FOREACH_ENTRY(exit_entries, exit_entry) {
                                create_exit_at(qobject_to(QDict, qlist_entry_obj(exit_entry)));
                        }
                } else if (!strcmp(entry->key, "interrupt_firing")){
                        configure_interrupt_firing_strategy(qobject_to(QDict, entry->value));
                }

                entry = qdict_next(conf, entry);
        }

#ifdef DEBUG
        print_configuration();
#endif

        create_cpu(machine, conf);
}

static void configurable_machine_init(MachineClass *mc)
{
    static const char * const valid_cpu_types[] = {
        ARM_CPU_TYPE_NAME("cortex-m7"),
        NULL
    };

    mc->desc = "rehosting and fuzzing";
    mc->init = machine_init;
    mc->valid_cpu_types = valid_cpu_types;
}

DEFINE_MACHINE("rehost-fuzzing", configurable_machine_init)