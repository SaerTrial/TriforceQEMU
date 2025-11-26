#include "afl.h"

extern target_ulong afl_start_code, afl_end_code;
static bool input_already_given = false;
uint8_t *fuzz = NULL;
target_ulong fuzz_size = 0;
target_ulong fuzz_cursor = 0;
target_ulong startForkserver(CPUArchState *env, target_ulong enableTicks);
target_ulong getWork(CPUArchState *env, target_ulong ptr, target_ulong sz);
target_ulong startWork(CPUArchState *env, target_ulong ptr);
target_ulong doneWork(target_ulong val);
const char *peekStrZ(CPUArchState *env, target_ulong ptr, int maxlen);
bool getFuzz(uint8_t *buf, uint32_t size);
void loadFuzz(void);


void loadFuzz(void) {
    FILE *fp;
    
    assert(aflStart == 1);

    fp = fopen(aflFile, "rb");
    if(!fp) {
        perror(aflFile);
        exit(1);
    }

    fseek(fp, 0L, SEEK_END);
    target_ulong _size = ftell(fp);
    fuzz_size = _size;
    fseek(fp, 0L, SEEK_SET); 

    if ( (fuzz = malloc(_size+1)) == NULL ) {
        exit(1);
    }

    if (fread(fuzz, _size, 1, fp) == 0) {
        exit(1);
    }

    fclose(fp);
}



/* get fuzzing inputs */
bool getFuzz(uint8_t *buf, uint32_t size) {

    if(!input_already_given){
        loadFuzz();
        input_already_given = true;
    }

    if(size && fuzz_cursor + size <= fuzz_size) {
        qemu_log_mask(LOG_AFL, "[NATIVE FUZZ] Returning %d fuzz bytes\n", size); 
        memcpy(buf, &fuzz[fuzz_cursor], size);
        fuzz_cursor += size;
        return true;
    }
    else {
        qemu_log_mask(LOG_AFL, "[NATIVE FUZZ] Running out of inputs \n"); 
        free(fuzz);
        doneWork(0);
    }

    return false;
}

target_ulong startForkserver(CPUArchState *env, target_ulong enableTicks)
{
    //printf("pid %d: startForkServer\n", getpid()); fflush(stdout);
    if(afl_fork_child) {
        /* 
         * we've already started a fork server. perhaps a test case
         * accidentally triggered startForkserver again.  Exit the
         * test case without error.
         */
        _exit(0);
    }
#ifdef CONFIG_USER_ONLY
    /* we're running in the main thread, get right to it! */
    afl_setup();
    afl_forkserver(env);
#else
    /*
     * we're running in a cpu thread. we'll exit the cpu thread
     * and notify the iothread.  The iothread will run the forkserver
     * and in the child will restart the cpu thread which will continue
     * execution.
     * N.B. We assume a single cpu here!
     */
    aflEnableTicks = enableTicks;
    afl_wants_cpu_to_stop = 1;
#endif
    return 0;
}

/* copy work into ptr[0..sz].  Assumes memory range is locked. */
target_ulong getWork(CPUArchState *env, target_ulong ptr, target_ulong sz)
{
    target_ulong retsz;
    FILE *fp;
    unsigned char ch;
    //printf("pid %d: getWork %lx %lx\n", getpid(), ptr, sz);fflush(stdout);
    assert(aflStart == 0);
    fp = fopen(aflFile, "rb");
    if(!fp) {
         perror(aflFile);
         return -1;
    }
    retsz = 0;
    while(retsz < sz) {
        if(fread(&ch, 1, 1, fp) == 0)
            break;
        cpu_stb_data(env, ptr, ch);
        retsz ++;
        ptr ++;
    }
    fclose(fp);
    return retsz;
}

target_ulong startWork(CPUArchState *env, target_ulong ptr)
{
    target_ulong start, end;
    input_already_given = false;
    // qemu_log("pid %d: ptr %lx\n", getpid(), ptr);
    start = cpu_ldq_data(env, ptr);
    end = cpu_ldq_data(env, ptr + sizeof start);
    // qemu_log("pid %d: startWork %x - %x\n", getpid(), start, end);

    afl_start_code = start;
    afl_end_code   = end;
    aflGotLog = 0;
    aflStart = 1;
    // qemu_log("aflStart = %d\n", aflStart);
    return 0;
}

target_ulong doneWork(target_ulong val)
{
    //printf("pid %d: doneWork %lx\n", getpid(), val);fflush(stdout);
    assert(aflStart == 1);
/* detecting logging as crashes hasnt been helpful and
   has occasionally been a problem.  We'll leave it to
   a post-analysis phase to look over dmesg output for
   our corpus.
 */
#ifdef LETSNOT 
    if(aflGotLog)
        exit(64 | val);
#endif
    _exit(val); /* exit forkserver child */
}

uint32_t helper_aflCall32(CPUArchState *env, uint32_t code, uint32_t a0, uint32_t a1) {
    return (uint32_t)helper_aflCall(env, code, a0, a1);
}

uint64_t helper_aflCall(CPUArchState *env, uint64_t code, uint64_t a0, uint64_t a1) {
    qemu_log_mask(LOG_AFL, "helper_aflCall(%p, %ld, %ld, %ld)\n", env, code, a0, a1);
    switch(code) {
    case 1: return startForkserver(env, a0);
    case 2: return getWork(env, a0, a1);
    case 3: return startWork(env, a0);
    case 4: return doneWork(a0);
    default: return -1;
    }
}

/* return pointer to buf filled with strz from ptr[0..maxlen] */
const char *
peekStrZ(CPUArchState *env, target_ulong ptr, int maxlen)
{
    static char buf[0x1000];
    int i;
    if(maxlen > sizeof buf - 1)
        maxlen = sizeof buf - 1;
    for(i = 0; i < maxlen; i++) {
        char ch = cpu_ldub_data(env, ptr + i);
        if(!ch)
            break;
        buf[i] = ch;
    }
    buf[i] = 0;
    return buf;
}

void helper_aflInterceptLog(CPUArchState *env)
{
    if(!aflStart)
        return;
    aflGotLog = 1;
    
#ifdef TARGET_X86_64
    FILE *fp = NULL;
    if(fp == NULL) {
        fp = fopen("logstore.txt", "a");
        if(fp) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            fprintf(fp, "\n----\npid %d time %ld.%06ld\n", getpid(), (u_long)tv.tv_sec, (u_long)tv.tv_usec);
        }
    }
    if(!fp) 
        return;
    
    target_ulong stack = env->regs[R_ESP];;
    //target_ulong level = env->regs[R_ESI]; // arg 2
    target_ulong ptext = cpu_ldq_data(env, stack + 0x8); // arg7
    target_ulong len   = cpu_ldq_data(env, stack + 0x10) & 0xffff; // arg8
    const char *msg = peekStrZ(env, ptext, len);
    fprintf(fp, "%s\n", msg);
#endif
}

void helper_aflInterceptPanic(void)
{
    if(!aflStart)
        return;
    qemu_log_mask(LOG_AFL,
                      "%s\n", __func__);
    _exit(32);
}

