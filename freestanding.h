#ifndef FREESTANDING_H
#define FREESTANDING_H




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
#define MAP_FIXED_NOREPLACE 0x100000

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2


#define ET_EXEC 0x02

typedef long ssize_t;

long lseek(int fd,long offset, int whence);
long syscall6(long sys_number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6);
ssize_t read(int fd, void *buf, size_t count);
void print(const char *string);
int open( const char *path,int flag);
int close(int fd);
void* mmap(void *addr,size_t len, int prot, int flag, int fd, long offset);
int munmap(void *addr, size_t length);
void *memcpy(void *restrict dest, const void *restrict src, size_t length);
bool memcmp(const void *restrict ptr1, const void *restrict ptr2 , size_t length);
void *memset(void *dest, int value, size_t count);
int getuid();
void print_hex(uint64_t number);
unsigned int sys_setresgid(unsigned int real_gid, unsigned int egid, unsigned int sgid);
unsigned int sys_setresuid(unsigned int real_uid, unsigned int euid, unsigned int suid);
unsigned int sys_getuid();
bool strcmp(char *str1, char *str2);


#endif
