#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PROT_NONE 0X0
#define PROT_READ 0X1
#define PROT_WRITE 0X2
#define PROT_EXEC 0X4

#define MAP_SHARED 0X1
#define MAP_PRIVATE 0X2
#define MAP_ANONYMOUS 0X20
#define MAP_FAILED ((void*)-1)
#define MAP_FIXED 0x10


#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

extern int main(int argc, char *argv[] , char *enpv[]);



typedef long ssize_t;
//============================================================================ all the function in this file
void *memcpy(void *restrict dest, const void *restrict src, size_t length);                                       
long syscall6(long sys_number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6);
ssize_t read(int fd, void *buf, size_t count);
void print(char *string);
int open(char *path,int flag);
int close(int fd);
void* mmap(void *addr,size_t len, int prot, int flag, int fd, long offset);
int munmap(void *addr, size_t length);
int getuid();
void print_hex(uint64_t number);
unsigned int sys_setresgid(unsigned int real_gid, unsigned int egid, unsigned int sgid);
unsigned int sys_setresuid(unsigned int real_uid, unsigned int euid, unsigned int suid);
unsigned int sys_getuid();
//============================================================================



long syscall6(long sys_number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6){           //general syscall for all the syscalls
    long ret;
    register long r10 __asm__("r10") = arg4;
    register long r8 __asm__("r8") = arg5;
    register long r9 __asm__("r9") = arg6;

    __asm__ volatile(
        "syscall"
        :"=a"(ret)
        :"a"(sys_number),
        "D"(arg1),"S"(arg2),"d"(arg3),"r"(r10),"r"(r8),"r"(r9)
        :"rcx","r11","memory"
    );
    return ret;
}



void _exit(int code){                               //exit
    syscall6(60,(long)code,0,0,0,0,0);
    __builtin_unreachable();
}





void _start2(long *stack){              //_start
    int argc = (int)stack[0];
    char **argv = (char**)&stack[1];
    char **envp = argv + argc + 1;
    int ret = main(argc, argv , envp);
    _exit(ret);
    __builtin_unreachable();
}
__attribute__((noreturn))
void __attribute__ ((naked)) _start(void){
    __asm__ volatile(
        "xor %%rbp, %%rbp\n"
        "mov %%rsp, %%rdi\n"
        "and $-16, %%rsp\n"
        "jmp _start2\n"
        "hlt\n"
        :
        :
        :"memory"

    );
}




ssize_t read(int fd, void *buf, size_t count){          //read
    
    return (ssize_t)syscall6(0,(long)fd,(long)buf,(long)count,0,0,0);
  
}



void print(char *string){                           //write (output)(print)
    long len = 0;
    unsigned long ret;
    while(string[len])
        len++;
    char buf[len+1];
    buf[len] = '\n';
    for(int i=0; i<len;i++){
        buf[i] = string[i];
    }
    syscall6(1,1,(long)buf,(long)len+1,0,0,0);
  

}   


int open(char *path,int flag){                      //open file
  
   return (int)syscall6(2,(long)path,(long)flag,0,0,0,0);
    
}

int close(int fd){                      //close file
    long ret = syscall6(3,(long)fd,0,0,0,0,0);
    if(ret<0){
        print("couldt close the file. there is no such file!");
    }
    return (int)ret;
}




void* mmap(void *addr,size_t len, int prot, int flag, int fd, long offset){                //map memory
   
   return (void*)syscall6(9,(long)addr,(long)len,(long)prot,(long)flag,(long)fd,offset);
    
}


int munmap(void *addr, size_t length){                                                  //free 
    return (int)syscall6(11,(long)addr,(long)length,0,0,0,0);
}


int getuid(){                                                                           //user id root normal user
  
    return (int)syscall6(102,0,0,0,0,0,0);
}

void *memcpy(void *restrict dest, const void *restrict src, size_t length){                             //memory copy         
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    for(int i=0;i<length;i++){
        d[i] = s[i];
    }
    return dest;
}

void *memset(void *dest, int value, size_t count){                                                  //memory set
    unsigned char *d = (unsigned char *)dest;
    for(int i=0;i<count;i++){
        d[i] = (unsigned char)value;
    }
    return dest;
}


bool memcmp(const void *restrict ptr1, const void *restrict ptr2 , size_t length){                          //memory compare
    const unsigned char *p1 = (const unsigned char *)ptr1;
    const unsigned char *p2 = (const unsigned char *)ptr2;
    for(int i=0;i<length;i++){
        if(p1[i] != p2[i]){
            return 0;
        }
    }
    return 1;
}






long lseek(int fd,long offset, int whence){
    return syscall6(8, fd, offset, whence, 0, 0, 0);
}

unsigned int sys_setresgid(unsigned int real_gid, unsigned int egid, unsigned int sgid){
    return syscall6(119,real_gid,egid,sgid,0,0,0);
}
unsigned int sys_setresuid(unsigned int real_uid, unsigned int euid, unsigned int suid){
    return syscall6(117,real_uid,euid,suid,0,0,0);
}
unsigned int sys_getuid(){
    return syscall6(102,0,0,0,0,0,0);
}


bool strcmp(char *str1, char *str2){
    int len1=0;
    int len2 =0;
    int i =0;
    while(str1[i] != '\0'){
        len1++; 
        i++;
    }
    i=0;
    while(str2[i] != '\0'){
        len2++;
        i++;
    }
    if(len2 != len1){
        return false;
    }
    for(int i = 0; i<len1;i++){
        if(str1[i] != str2[i]){
            return false;
        }
    }
    return true;
}






void print_hex(uint64_t number){                                                                        //print hex

    const char hex_d[]= "0123456789ABCDEF";
    uint64_t temp = number;
    if(number ==0){
        print("0x0");
        return;
    }
    int len = 0;
    while(temp>0){
        len++;
        temp >>=4;
    }
    char string[len+2];
    string[0]='0';
    string[1]='x';
    int index = len+1;
    while(number > 0){
        string[index] = hex_d[number & 0xF];
        index--;
        number >>=4;
    }
    print(string);
    return;

}







