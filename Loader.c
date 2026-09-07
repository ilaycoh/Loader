
// gcc -static -no-pie -Wl,-Ttext-segment=0x70000000 -nostdlib -fno-builtin -g -fno-stack-protector loader.c freestanding.c -o loader


#include "freestanding.h"
#include <elf.h>
#define max_ranges 256
#define MAX_SYMBOLS 4096
#define STACK_SZ 0x10000

#define program "main"

//----------------------------------------------structs----------------------------
struct MemoryRange{
    unsigned long long start;
    unsigned long long end;
};

struct Global_sym{
    char *name;
    unsigned long long addr;
};

struct TLS{
    unsigned long long p_offset;
    unsigned long long p_filesz;
    unsigned long long p_memsz;
    unsigned long long p_align;
    unsigned long long tls_offset;
    int fd;
};

struct init{
    unsigned long long addr;
    unsigned long size;
};
//------------------------------------------functions-----------------------------------
int translate_flags(int p_flags){
    int port =0;
    if(p_flags & 4) port |= 1;
    if(p_flags & 2) port |= 2;
    if(p_flags & 1) port |= 4;
    return port;
}
static unsigned char ascii_to_hex(char c){
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0xFF;
}
void range_from_the_string(const char *line, unsigned long long *start , unsigned long long *end){      //calc the maps range from str to num
    unsigned long long start_val = 0;
    unsigned long long end_val = 0;
    int i = 0;
    while(line[i] != '-' && line[i] != '\0'){               //loop for the first number
        unsigned char val = ascii_to_hex(line[i]);
        if(val != 0xFF){
           start_val =  (start_val<<4) | val;
        }
        i++;
    }

    if(line[i] == '-'){
        i++;
    }
    while(line[i] != ' ' && line[i] != '\0'){
        unsigned char val = ascii_to_hex(line[i]);
        if(val != 0xff){
            end_val = (end_val<<4) | val;
        }
        i++;
    }
    *start = start_val;
    *end = end_val;
}

void build_path(char *buffer , char *dir,char *file){       //build a path for the so
    char *ptr_buf = buffer;
    int i = 0;
    int j = 0;
    while(dir[i] != '\0'){
        buffer[i] = dir[i];
        i++;
    }
    while(file[j] != '\0'){
        buffer[i] = file[j];
        i++;
        j++;
    }
    buffer[i] = '\0';
}

//-----------------------------------------------main----------------------------
int main(int argc, char *argv[], char *envp[]){
    int fd = open(program,0x0);
    if(fd < 0){
        print("error in open the file");
        return 0;

    }
    Elf64_Ehdr pro_header;

    ssize_t header_reading = read(fd,&pro_header,64);
    if(header_reading < 0 ){
        print("error reading the header");
        return 0;
    }

    int count_headers = pro_header.e_phnum;

   
    unsigned int phdr_size = pro_header.e_phentsize;
  

    int loader_maps = open("/proc/self/maps",0x0);
    char maps_buffer[8192];
    ssize_t maps_buffer_read = read(loader_maps,&maps_buffer,8192);
    if(maps_buffer_read<0){
        print("faild to read /proc/self/maps");
        return 0;
    }
    char *line_start = maps_buffer;
    char *ptr = maps_buffer;
    static struct MemoryRange protected_ranges[max_ranges];
    static int count_ranges = 0;
    while(*ptr != '\0'){
        if(*ptr == '\n'){
            *ptr = '\0';

        
            unsigned long long temp_start;
            unsigned long long temp_end;
            range_from_the_string(line_start, &temp_start,&temp_end);
            if(count_ranges < max_ranges){
                protected_ranges[count_ranges].start = temp_start;
                protected_ranges[count_ranges].end = temp_end;
                count_ranges++;
            }
            else{
                print("Warning: you got to the max maps");
            }


            *ptr = '\n';
            line_start = ptr + 1;
        }
        ptr++;
    }

    Elf64_Addr base_addr = 0;
    bool first = true;
    Elf64_Dyn *dyn_table = 0;
    Elf64_Phdr pro_phdr;
    unsigned long long load_bias = 0;
    if(pro_header.e_type == ET_EXEC){
        load_bias = 0;
    }
    else{ 
        unsigned long long min_vaddr = 0xfffffffffff;
        unsigned long long max_vaddr = 0;
        for(int i =0 ; i<count_headers;i++){
            lseek(fd,pro_header.e_phoff + (long)i * pro_header.e_phentsize, SEEK_SET);
            ssize_t phdr_read = read(fd,&pro_phdr,phdr_size);
            if(pro_phdr.p_vaddr < min_vaddr){
                min_vaddr = pro_phdr.p_vaddr;
            }
            if(max_vaddr < (pro_phdr.p_vaddr + pro_phdr.p_memsz)){
                max_vaddr = pro_phdr.p_vaddr + pro_phdr.p_memsz;
            }

        }
        unsigned long long total;
        unsigned long long aligned_min = min_vaddr - (min_vaddr % 4096);
        unsigned long long aligned_max = ((max_vaddr + 4095) / 4096) * 4096;
        total = aligned_max - aligned_min;


        void *anchor = mmap(NULL,total,PROT_NONE,MAP_PRIVATE | MAP_ANONYMOUS,-1,0);
        if(anchor == MAP_FAILED){
            print("couldnt mmap");
            return 0;
        }
        if((unsigned long long)anchor < aligned_min){
            print("cant load something worg with the elf");
            return 0;
        }
        print("f");
        print_hex(aligned_min);
        load_bias = (unsigned long long)(anchor - aligned_min);
    }

   
    struct TLS tls_table[64];
    int tls_table_index = 0;
    int tls_count = 0;
    base_addr = load_bias;
    unsigned long long e_ph = base_addr + pro_header.e_phoff;
    for(int i =0 ; i<count_headers;i++){
        lseek(fd,pro_header.e_phoff + (long)i * pro_header.e_phentsize ,SEEK_SET);

        ssize_t phdr_read = read(fd,&pro_phdr,phdr_size);

        if(phdr_read < 0){
            print("error in reading 1 segment");
        }
        if(pro_phdr.p_type == PT_DYNAMIC){
            dyn_table = (Elf64_Dyn *)(load_bias + pro_phdr.p_vaddr);
        }

        if(pro_phdr.p_type == PT_TLS){
            tls_table[tls_table_index].p_offset = pro_phdr.p_offset;
            tls_table[tls_table_index].p_align = pro_phdr.p_align;
            tls_table[tls_table_index].p_filesz = pro_phdr.p_filesz;
            tls_table[tls_table_index].p_memsz = pro_phdr.p_memsz;
            tls_table[tls_table_index].fd = fd;
            tls_table_index++;
            tls_count++;
        }

        

        if(pro_phdr.p_type == PT_LOAD){
            
         

            unsigned long page_offset = pro_phdr.p_vaddr % 4096;
            unsigned long aligned_vaddr =  load_bias + (pro_phdr.p_vaddr - page_offset);  // + load_bias 
            unsigned long aligned_size = pro_phdr.p_memsz + page_offset;
            aligned_size = ((aligned_size + 4095) / 4096) * 4096;
            unsigned long aligned_offset = pro_phdr.p_offset - page_offset;
            int port = translate_flags(pro_phdr.p_flags);
            
            unsigned long elf_start = aligned_vaddr;
            unsigned long elf_end = aligned_vaddr + aligned_size;
            
            for(int j =0; j<count_ranges;j++){
                if(elf_start < protected_ranges[j].end && elf_end > protected_ranges[j].start){
                    print("Error: cant let you to overwrite my loader maps ;)");
                    return 1;
                }


            }
            void *map = mmap((void *)aligned_vaddr, aligned_size , port  ,  MAP_PRIVATE  | MAP_FIXED , fd, aligned_offset);
            if(map == MAP_FAILED){
                print("maped faild");
                return 0;
            }
           
           
            
            lseek(fd,pro_phdr.p_offset,SEEK_SET);
         

            //ssize_t map_read = read(fd , (void *)pro_phdr.p_vaddr, pro_phdr.p_filesz);
            //if(map_read > 0){
                //print("good!!!");
                //count++;
            //}

        }
       

    }
    
    struct init init_table[1024];        //for so
    int init_index =0;
    struct init main_init[1024];        //for the program
    int main_init_index = 0;
    if(dyn_table != NULL){
        unsigned long rela_size = 0;
        unsigned long rela_ent = 0;
        Elf64_Rela *rela_table = NULL;
        unsigned long long d_needed_list[64];
        char *d_strtab = NULL;
        Elf64_Sym *d_symtab = 0;
        Elf64_Rela *d_pltrela = NULL;
        unsigned long d_pltrelsz = 0;
        int needed_count = 0;
        unsigned int d_syment = 0;

        

        struct Global_sym global_sym_table[MAX_SYMBOLS];
        

        for(int i = 0; dyn_table[i].d_tag != DT_NULL;i++){
            switch(dyn_table[i].d_tag){
                case DT_RELA: rela_table = (Elf64_Rela *)(base_addr + dyn_table[i].d_un.d_ptr); break;
                case DT_RELASZ: rela_size =(unsigned long )dyn_table[i].d_un.d_val;break;
                case DT_RELAENT: rela_ent = dyn_table[i].d_un.d_val; break;
                case DT_NEEDED: d_needed_list[needed_count] = dyn_table[i].d_un.d_val;needed_count++ ;break;
                case DT_STRTAB:  d_strtab = (char *)(base_addr + dyn_table[i].d_un.d_ptr) ; break;
                case DT_SYMTAB:  d_symtab =(Elf64_Sym *) (base_addr + dyn_table[i].d_un.d_ptr) ; break;
                case DT_JMPREL:  d_pltrela = (Elf64_Rela *)(base_addr + dyn_table[i].d_un.d_ptr); break;
                case DT_PLTRELSZ:d_pltrelsz = dyn_table[i].d_un.d_val; break; 
                case DT_SYMENT: d_syment = (unsigned long)dyn_table[i].d_un.d_val;break;
                case DT_INIT_ARRAY: main_init[main_init_index].addr = base_addr + dyn_table[i].d_un.d_ptr;break;
                case DT_INIT_ARRAYSZ: main_init[main_init_index].size = dyn_table[i].d_un.d_val;main_init_index++;break;
            }
        }
      
       
        
        unsigned int count_sym = ((unsigned long long)d_strtab - (unsigned long long)d_symtab) / d_syment;
        int global_sym_table_index = 0;
        print_hex(count_sym);
        for(int i = 0;i<count_sym;i++){
            if(d_symtab[i].st_shndx == SHN_UNDEF){
                print("not mine");
                continue;

            }

           struct Global_sym curr_sym;
           char * name = (char *)(d_symtab[i].st_name + d_strtab);
           curr_sym.name = name;
           unsigned long long d_addr = (unsigned long long)base_addr + d_symtab[i].st_value;
           curr_sym.addr = d_addr;
           global_sym_table[global_sym_table_index] = curr_sym;
           global_sym_table_index++;
           
        }
        
        








        char *dynstr = (char *)(d_strtab);
        char *filenames[64];
        int count_files = 0;
        for(int i= 0; i<needed_count;i++){
            if(d_needed_list[i] != 0){
                filenames[i] = &dynstr[d_needed_list[i]];
                count_files++;
            }
            else{
                break;
            }
        }

        //search for the files here. you have a arr of the names

        //try to open the files with the full path. if the file opend then good, if not its not there.if all failed then return
       
        char *win_paths[64];
        int win_fds[64];
        for(int i = 0;i<needed_count;i++){
            char *win_path;
            int win_fd = 0;
            bool found = false;
            char buffer1[256];
            char buffer2[256];
            char buffer3[256];

            char *path1 = buffer1;
            char *path2 = buffer2;
            char *path3 = buffer3;
        
            build_path(buffer1,"/usr/local/lib/",filenames[i]);
            build_path(buffer2,"/usr/lib/",filenames[i]);
            build_path(buffer3,"/lib/",filenames[i]);
            int fd1 = open(path1,0);
            int fd2 = open(path2,0);     
            int fd3 = open(path3,0);
       
            if(fd3 >= 0){
                win_path = path3;
                win_fd = fd3;
                found = true;
            }
            if(fd2 >= 0){
                if(win_fd == fd3){
                    close(fd3);
                }
                win_path = path2;
                win_fd = fd2;
                found = true;
            }
            if(fd1 >= 0){
                if(win_fd == fd2){
                    close(fd2);
                }
                win_path = path1;
                win_fd= fd1;
                found = true;
            }
            if(!found){
                print("this so didnt open ");
                print(filenames[i]);
            }
            win_paths[i] = win_path;
            win_fds[i] = win_fd;
        }

        //load the so`s
      
        Elf64_Phdr so_pro_phdr;
        for(int i= 0; i <needed_count ; i++){
            Elf64_Ehdr so_header;
            ssize_t so_header_read = read(win_fds[i],&so_header,64);
            if(so_header_read < 0){
                print("couldnt read one of the so header");
                return 0;
            }
            int so_count_phdr = so_header.e_phnum;
            unsigned int so_phdr_sz = so_header.e_phentsize;
            unsigned long long so_start_addr = 0xfffffffffff;
            unsigned long long so_end_addr = 0; 
            for(int j=0;j<so_count_phdr;j++){
                lseek(win_fds[i],so_header.e_phoff + (long)j * so_phdr_sz ,SEEK_SET);

                ssize_t so_read_seg = read(win_fds[i],&so_pro_phdr , so_phdr_sz);
                if(so_read_seg <0){
                    print("failed at reading one of the segments in one of the so");
                    return 0;
                }
                if(so_pro_phdr.p_type == PT_LOAD){
                    if(so_start_addr > so_pro_phdr.p_vaddr){
                        so_start_addr = so_pro_phdr.p_vaddr;
                    }
                    if(so_end_addr < so_pro_phdr.p_vaddr + so_pro_phdr.p_memsz){
                        so_end_addr = so_pro_phdr.p_vaddr + so_pro_phdr.p_memsz;
                    }

                }
               
            }
            unsigned long long so_aligned_st = so_start_addr - (so_start_addr % 0x1000);
            unsigned long long so_aligned_ed = ((so_end_addr + 4095) / 4096) * 4096;
            unsigned long long so_aligned_size = so_aligned_ed - so_aligned_st;
            
            void *so_base = mmap(NULL,so_aligned_size,PROT_NONE,MAP_PRIVATE | MAP_ANONYMOUS,-1,0);
            if(so_base == MAP_FAILED){
                print("couldnt map of of the so");
                return 0;
            }
            

            unsigned long long so_base_load = (unsigned long long)so_base - so_aligned_st;
            for(int j =0; j<count_ranges;j++){
             
                if(so_base_load + so_aligned_st < protected_ranges[j].end && so_base_load + so_aligned_ed > protected_ranges[j].start){
                    print("Error: cant let you to overwrite my loader maps ;)");
                    return 1;
                }
            }


            Elf64_Dyn *so_dyn_table = 0;            //for rela

           
            for(int j= 0; j<so_count_phdr;j++){
                lseek(win_fds[i],so_header.e_phoff + (long)j * so_phdr_sz ,SEEK_SET);
               
                ssize_t so_read_seg = read(win_fds[i],&so_pro_phdr , so_phdr_sz);
                if(so_read_seg <0){
                    print("failed at reading one of the segments in one of the so");
                    return 0;
                }
                if(so_pro_phdr.p_type == PT_DYNAMIC){
                    so_dyn_table = (Elf64_Dyn *)(so_base_load + so_pro_phdr.p_vaddr);
                }

                if(so_pro_phdr.p_type == PT_TLS){                                   //TLS
                    tls_table[tls_table_index].p_offset = so_pro_phdr.p_offset;
                    tls_table[tls_table_index].p_align = so_pro_phdr.p_align;
                    tls_table[tls_table_index].p_filesz = so_pro_phdr.p_filesz;
                    tls_table[tls_table_index].p_memsz = so_pro_phdr.p_memsz;
                    tls_table[tls_table_index].fd = win_fds[i];
                    tls_table_index++;
                    tls_count++;
                }
                if(so_pro_phdr.p_type == PT_LOAD){
                    int so_prot = translate_flags(so_pro_phdr.p_flags);
                    unsigned long so_page_offset = so_pro_phdr.p_vaddr % 4096 ; 
                    unsigned long long so_aligned_memsz = (( so_page_offset + so_pro_phdr.p_memsz + 4095) / 4096) *4096;
                    unsigned long long so_aligned_offset = so_pro_phdr.p_offset - (so_pro_phdr.p_offset % 0x1000);
                    unsigned long long so_aligned_vaddr = so_pro_phdr.p_vaddr - ( so_pro_phdr.p_vaddr %4096);
                    void *so_map = mmap((void *)(so_aligned_vaddr + so_base_load),so_aligned_memsz,so_prot,MAP_PRIVATE | MAP_FIXED ,win_fds[i],so_aligned_offset );
                    if(so_map == MAP_FAILED){
                        print("faild to map one of the  so segments :(");
                        return 0;
                    }
                }
            }
            
            unsigned long so_rela_size = 0;
            unsigned long so_rela_ent = 0;
            Elf64_Rela *so_rela_table = NULL;
            char *so_strtab;
            Elf64_Sym *so_symtab;
            unsigned int so_syment = 0;


            if(so_dyn_table != NULL){
               
                for(int j =0; so_dyn_table[j].d_tag != DT_NULL ; j++){
                    switch(so_dyn_table[j].d_tag){
                        case DT_RELA: so_rela_table = (Elf64_Rela *)(so_base_load + so_dyn_table[j].d_un.d_ptr); break;
                        case DT_RELASZ: so_rela_size = so_dyn_table[j].d_un.d_val;break;
                        case DT_RELAENT: so_rela_ent = so_dyn_table[j].d_un.d_val; break;
                        case DT_STRTAB: so_strtab = (char *)(so_dyn_table[j].d_un.d_ptr + so_base_load);break;
                        case DT_SYMTAB: so_symtab = (Elf64_Sym *)(so_dyn_table[j].d_un.d_ptr + so_base_load);break;
                        case DT_SYMENT: so_syment = (unsigned int)(so_dyn_table[j].d_un.d_val);break;
                        case DT_INIT_ARRAY: init_table[init_index].addr = so_base_load + so_dyn_table[j].d_un.d_ptr;break;
                        case DT_INIT_ARRAYSZ: init_table[init_index].size = so_dyn_table[j].d_un.d_val;init_index++;break;
                    }
                }
            }
            unsigned int so_count_sym = 0;
            
            
            so_count_sym = ((unsigned long long)so_strtab - (unsigned long long)so_symtab)/so_syment;
          
    
            for(int j = 0 ; j<so_count_sym; j++){
                if(so_symtab[j].st_shndx == SHN_UNDEF){
                print("not mine");
                    continue;
                }
                struct Global_sym curr_sym;
                char *so_temp_name = (char *)((unsigned long long)so_strtab + so_symtab[j].st_name);
                unsigned long long so_temp_addr = (unsigned long long)so_symtab[j].st_value + so_base_load;
                curr_sym.addr = so_temp_addr;
                curr_sym.name = so_temp_name;
                print(so_temp_name);
                global_sym_table[global_sym_table_index] = curr_sym;
                global_sym_table_index++;
            }
            
            if(so_rela_ent != 0 && so_rela_table != NULL){
                int so_count_reloc = so_rela_size / so_rela_ent;

                for(int j =0; j< so_count_reloc; j++){
                    Elf64_Rela so_curr_rela = so_rela_table[j];
                    unsigned int so_type_rela = (so_curr_rela.r_info) & (0xffffffff);
                    if(so_type_rela == R_X86_64_RELATIVE){
                        unsigned long long so_hole_addr = so_base_load + so_curr_rela.r_offset;
                        for(int p = 0; p< count_ranges; p++){
                            if(so_hole_addr >= protected_ranges[p].start && so_hole_addr <= protected_ranges[p].end)
                            {
                                print("Error: cant let you to overwrite my loader maps ;)");
                                return 1;
                            }
                        }
                        unsigned long long *so_hole_addr_ptr = (unsigned long long *)(so_hole_addr);
                        *so_hole_addr_ptr = so_base_load + so_curr_rela.r_addend;

                    }
                }

            }
          
        }
     


        int global_sym_table_len =  global_sym_table_index+1;
      
        

        if(rela_ent != 0 && rela_table !=NULL){
            int count_reloc = rela_size / rela_ent;
       
            
            for(int i =0; i<count_reloc;i++){
                Elf64_Rela current_rela = rela_table[i];
                unsigned int type_rela = (current_rela.r_info) &(0xffffffff);
                if(type_rela == R_X86_64_RELATIVE){
                    unsigned long long hole_addr = base_addr + current_rela.r_offset;
                    for(int j=0; j<count_ranges;j++){
                        if(hole_addr >= protected_ranges[j].start && hole_addr <= protected_ranges[j].end){
                            print("Error: cant let you to overwrite my loader maps ;)");
                            return 1;
                        }  
                    }
                    unsigned long *hole_addr_ptr = (unsigned long *)(hole_addr);
                    *hole_addr_ptr = base_addr + current_rela.r_addend;
                }
                if(type_rela == R_X86_64_GLOB_DAT ){
                    unsigned long long hole_addr = base_addr + current_rela.r_offset;
                    for(int j=0; j<count_ranges;j++){
                        if(hole_addr >= protected_ranges[j].start && hole_addr <= protected_ranges[j].end){
                            print("Error: cant let you to overwrite my loader maps ;)");
                            return 1;
                        }  
                    }
                    unsigned long long *hole_addr_ptr = (unsigned long long *)(hole_addr);
                    unsigned long name_index = current_rela.r_info >> 32;
                    char *name_sym = d_strtab + name_index;
                    print("there is");
                    unsigned long long resolved_addr;
                    for(int j=0; j< global_sym_table_index; j++){
                        if(strcmp(name_sym, global_sym_table[j].name)){
                            resolved_addr = global_sym_table[j].addr;
                            break;
                        }
                    }
                    *hole_addr_ptr = resolved_addr;
                }
                
            }
           
        }

        if(d_pltrela != NULL){
            int count_plt_relas = d_pltrelsz / sizeof(Elf64_Rela);
            
            for(int i = 0; i<count_plt_relas; i++){
                Elf64_Rela plt_rela = d_pltrela[i];
                unsigned long rela_type = (plt_rela.r_info) & (0xffffffff);
                if(rela_type == R_X86_64_JUMP_SLOT){
                   unsigned long rela_name = (plt_rela.r_info) >> 32;
                   char *name = d_strtab + rela_name;
                   unsigned long long resolved_addr;
                   unsigned long long hole_addr = base_addr +  plt_rela. r_offset;
                   unsigned long long *hole_addr_ptr = (unsigned long long *)hole_addr;
                    
                    for(int j=0; j<count_ranges;j++){
                        if(hole_addr >= protected_ranges[j].start && hole_addr <= protected_ranges[j].end){
                            print("Error: cant let you to overwrite my loader maps ;)");
                            return 1;
                        }  
                    }
                  
                   for(int j =0 ; j< global_sym_table_len ; j++){
                        
                        if(strcmp(name , global_sym_table[j].name)){
                            
                            resolved_addr = global_sym_table[j].addr;
                            break;
                        }
                   }
                   *hole_addr_ptr = resolved_addr;
                }
            }
        }
        
    }
                                                                                                //libc
/* 
    unsigned  long new_argc = argc;             //stack preper
    char *new_argv[new_argc +1 ];
    new_argv[0] = program;
   
    int envp_count = 0;
   
    while(envp[envp_count] != NULL){
        envp_count++;
    }
    char *new_envp[envp_count +1];
    
    for(int i=0; i<envp_count; i++){
        new_envp[i]=envp[i];
        
    }
    
    Elf64_auxv_t auxv[8];
    
    auxv[7].a_type = (unsigned long)NULL;           //end

    auxv[0].a_type = AT_PHDR;
    auxv[0].a_un.a_val = e_ph;

    auxv[1].a_type = AT_PHENT;
    auxv[1].a_un.a_val = pro_header.e_phentsize;

    auxv[2].a_type = AT_PHNUM;
    auxv[2].a_un.a_val = pro_header.e_phnum;

    auxv[3].a_type = AT_ENTRY;
    auxv[3].a_un.a_val = load_bias + pro_header.e_entry;

    auxv[4].a_type = AT_PAGESZ;
    auxv[4].a_un.a_val = 0x1000;

    auxv[5].a_type = AT_RANDOM;
    auxv[5].a_un.a_val = (unsigned long)((unsigned long long*)(00000000000));

    auxv[6].a_type = AT_BASE;
    auxv[6].a_un.a_val = 0;
   
    void *stack_map = mmap(NULL,STACK_SZ, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1 , 0);
    print("stack");
    
    if(stack_map == MAP_FAILED){
        print("failed at mapping a stack for the program");
        return 0;
    }
    char *stack_top = (char *)stack_map + STACK_SZ;
    unsigned long sp = (unsigned long) stack_top;
    print_hex(sp);
    sp &= ~(unsigned long long)0xF;
    
    
    char *all_str[argc+envp_count];
    int all_str_index = 0;
    for(int i = 0; i<argc;i++){
        all_str[i] = new_argv[i];
        all_str_index++;
       
    }
    int in = 0;
    for(int i = all_str_index; i<argc+envp_count; i++){
        all_str[i] = envp[in];
        in++;
    }
    int argv_count = 0;
    int envp_index = 0;

    for(int i =0; i< argc + envp_count;i++){            //str
        
        char *str = all_str[i];
        int len=0;
        while(str[len] != '\0'){
            len++;
        }
        len++;

        sp -=len;
        char *new_addr = (char *)sp;
        for(int j =0; j<len;j++){
            new_addr[j] = str[j];
        }
        if(argv_count < argc){
            new_argv[argv_count] = new_addr;
            argv_count++;
        }
        else{
            new_envp[envp_index] = new_addr;
            
            envp_index++;
        }
        
    }
    print("hi");
    new_argv[argc] =NULL;
    new_envp[envp_count]=NULL;

              
    sp -= 8 * sizeof(Elf64_auxv_t);                 //auxv
    Elf64_auxv_t *new_auxv = (Elf64_auxv_t *)sp;
    for(int i= 0; i<8;i++){
        new_auxv[i] = auxv[i];
    }    
                 
    sp -= (envp_count * (sizeof(char *)));      
    char **new_s_envp = (char **)sp;
    for(int i = 0; i < envp_count;i++){
        new_s_envp[i] = new_envp[i];
    }


             
    sp -= (new_argc+1)*(sizeof(char *));             //argv
    char **new_s_argv = (char **)sp;
    for(int i =0; i<new_argc+1;i++){
        new_s_argv[i] = new_argv[i];
    }


  
    sp -= sizeof(new_argc);                                         //argc
    print("sp");
    print_hex(sp);
    unsigned long long *new_s_argc = (unsigned long long *)sp;
    *new_s_argc = (unsigned  long )new_argc;
    

    sp &= ~(unsigned long long)0xF;                                     



    if(tls_count >0){

        unsigned long long tls_total_memsz = 0;                                                         //TLS
        unsigned long long tls_place_table[64];

        unsigned long long tls_memsz = 8;
        tls_table_index++;
        for(int i=0; i<tls_table_index ; i++){
            tls_place_table[i] = tls_total_memsz;
            print_hex(tls_place_table[i]);
            unsigned long long curr_memsz = tls_table[i].p_memsz;
            unsigned long long curr_align = tls_table[i].p_align;
            unsigned long long aligned_tls_memsz;
            if(curr_align != 0)
                aligned_tls_memsz = ((curr_memsz + (curr_align-1))/curr_align)*curr_align;
            tls_total_memsz += aligned_tls_memsz;
        }
        
        void *tls_block_map = mmap(NULL,(size_t)tls_total_memsz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE , -1 ,0);
        if(tls_block_map == MAP_FAILED){
            print("failed to map tls blocks");
            return 0;
        }

        for(int i =0; i< tls_table_index; i++){
           long lseek_ch = lseek(tls_table[i].fd, (long)(tls_table[i].p_offset), SEEK_SET);
           if(lseek_ch < 0){
            print("faild lseek");
            return 0;
           }
           ssize_t tls_read = read(tls_table[i].fd, (void *)(tls_place_table[i] + tls_block_map), tls_table[i].p_memsz);
           print_hex((unsigned long long)(tls_place_table[i] + tls_block_map));
           if(tls_read < 0){
            print("failed read tls");
            return 0;
           }
        }

        char *start_block = (char *)tls_block_map;
        char *end_block = start_block + tls_total_memsz;
        
        __asm__ volatile(
            "mov $158, %%rax\n"
            "mov $0x1002, %%rdi\n"
            "mov %0, %%rsi\n"
            "syscall\n"
            :
            :"r"(end_block)
            : "rax", "rdi", "rsi", "rcx", "r11", "memory"
        );

        *(unsigned long long *)start_block = (unsigned long long)start_block;

        print("there is");
    }

    void (*global_init[1024])();
    
    int global_init_index =0;
    print("so");
    print_hex((unsigned long long)init_index);
    print_hex((unsigned long long)main_init_index);
    if(init_index != 0){                                                            //for so init
       for(int i= 0; i< init_index;i++){
            int init2_count =   init_table[i].size / sizeof(unsigned long long);
            
            Elf64_Addr *table =(Elf64_Addr *) init_table[i].addr;
            for(int j=0;j< init2_count;j++){
                if(table[j] != 0){
                    global_init[global_init_index] = ((void(*)())table[j]);
                    global_init_index++;
                }
            }
            
        }
        print("here");
    }
    if(main_init_index != 0){
        for(int i=0; i<main_init_index;i++){
            int init2_count = main_init[i].size / sizeof(unsigned long long);
            Elf64_Addr *table = (Elf64_Addr *) main_init[i].addr;
            for(int j=0; j< init2_count;j++){
                if(table[j] != 0){
                    global_init[global_init_index] = ((void(*)())table[j]);
                    global_init_index++;
                }
            }
        }

    }

    print("ok");
    int i =sys_getuid();
    for(int i=0; i< global_init_index+1; i++){
        if(global_init[i] != 0){
            print_hex((unsigned long long)global_init[i]);
            print("d");
            global_init[i]();
        }
    }*/
    print("he");
   
    






   

    print_hex((unsigned long long)1);        //for the attack from the python file
    
    
    unsigned int check = sys_setresgid(65534,65534,65534);
    if(check != 0){
        print("failed,cant let you run this program as root ;)");
        return 0;
    }
    unsigned int check2 = sys_setresuid(65534,65534,65534);
   
    if(check2 != 0){
        print("failed, cant let you to run this program as root ;)");
        return 0;
    }
   
   


   Elf64_Addr entry_point = load_bias + pro_header.e_entry;
    int a = sys_getuid();
    ((void(*)())entry_point)();
    print("?");


 
    return 0;
}
