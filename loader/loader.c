#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
 
#include "exec_parser.h"

/*structura care tine evidenta paginilor alocate*/
struct pageEvidence {
    unsigned int *pagesVect; /*stocheaza paginile mapate*/
    unsigned int pageCount; /*tine evidenta numarului de pagini mapate*/
};
 
static so_exec_t *exec;
static int fd; /*file descriptorul fisierului*/
static int pageSize; /*dimensiunea paginii*/
static struct sigaction old_handler; /*handler vechi*/
static struct sigaction handler; /*handler nou*/
 
/* handlerul nou pentru tratarea semnalului SIGSEGV */
static void segv_handler(int signum, siginfo_t *info, void *context)
{
    void *mmapAddr;
    int rc, already_mapped = 0; /*variabile de verificare*/
    int pageIndex, page_offset; /*informatii ale paginii*/

	/*in cazul unui acces necorespunzator la memorie sau se primeste altceva 
	decat SIGSEGV, apelez handlerul vechi*/
    if (signum != SIGSEGV || info->si_code == SEGV_ACCERR) {
        sigemptyset(&old_handler.sa_mask);
        old_handler.sa_sigaction(signum, info, context);
        return;
    } else {
 		
 		/*iterez prin toate segmentele*/
        for (int counter = 0; counter < exec->segments_no; counter++) {
            
            void* startAddr = (void *) exec->segments[counter].vaddr;
            struct pageEvidence *pgEv = exec->segments[counter].data;
            int mem_size = exec->segments[counter].mem_size;
 
            int size = mem_size / pageSize + 1;
            
            /*aloc spatiu pentru vectorul de pagini in cazul in care acesta nu 
            a fost alocat deja*/
            if (!pgEv->pagesVect) {
                pgEv->pagesVect = malloc(size * sizeof(int));
                if (!pgEv->pagesVect) {
                    perror("Eroare alocare pagina!\n");
                    exit(EXIT_FAILURE);
                }
            }
            
            void *endAddr = (void *) (startAddr + mem_size);
 			
 			/*verific daca adresa cautata este in intervalul segmentului 
 			curent. Daca nu, se apeleaza handlerul vechi*/
            if (info->si_addr > endAddr || info->si_addr < startAddr) {
                continue;
            } else {
            
            	/*indexul paginii care a dat page fault*/
                pageIndex = (info->si_addr - startAddr) / pageSize;
                page_offset = exec->segments[counter].offset
                            + pageIndex * pageSize;
 				/*verific daca pagina a fost mapata*/
                for (int pageIter = 0; pageIter < pgEv->pageCount; pageIter++) {
 					
 					/*daca o pagina din vectorul de pagini coincide cu o pagina 
 					deja mapata*/
                    if (pgEv->pagesVect[pageIter] == pageIndex) {
                        already_mapped = 1;
                        break;
                    }
                }
 				
                if (!already_mapped) {
                	//mapez pagina
                    mmapAddr = mmap(startAddr + pageIndex * pageSize,
                            pageSize, PROT_WRITE, MAP_SHARED
                            | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                    if (mmapAddr < 0) {
                        perror("Eroare la maparea paginii!\n");
                        exit(EXIT_FAILURE);
                    }
 
                    if (exec->segments[counter].file_size > 
                    pageIndex * pageSize) {
                        lseek(fd, page_offset, SEEK_SET);
 
                        if (exec->segments[counter].file_size >= 
                        (pageIndex + 1) * pageSize) {
                            rc = read(fd, mmapAddr, pageSize);
                            if (rc == -1) {
                                perror("Eroare2 read!\n");
                                exit(EXIT_FAILURE);
                            }
                        } else {
                            rc = read(fd, mmapAddr,
                                    exec->segments[counter].file_size - 
                                    pageIndex * pageSize);
                            if (rc == -1) {
                                perror("Eroare1 read!\n");
                                exit(EXIT_FAILURE);
                            }
                        }
                    }
 					
 					/*adaugam pagina in vector si incrementam contorul*/
                    pgEv->pagesVect[pgEv->pageCount] = pageIndex;
                    pgEv->pageCount++;
 					
 					/*setez permisiunile paginii*/
                    if (mprotect(mmapAddr, pageSize, 
                    exec->segments[counter].perm) < 0) {
                        perror("Eroare mprotect!\n");
                        exit(EXIT_FAILURE);
                    }
                    return;
                }
            }
        }
        
        if (!already_mapped)
            old_handler.sa_sigaction(signum, info, context);
 
    }
}

/*initializez handlerul nou pentru tratarea semnalului SIGSEGV*/
int so_init_loader(void)
{
	/*noul handler*/
    if (sigemptyset(&handler.sa_mask) < 0) {
        perror("Eroare sigemptyset!\n");
        exit(EXIT_FAILURE);
    }
    
 	/*tratarea semnalului SIGSEGV*/
    if (sigaddset(&handler.sa_mask, SIGSEGV) < 0) {
        perror("Eroare sigaddset\n");
        exit(EXIT_FAILURE);
    }
 
    handler.sa_sigaction = segv_handler;
    if (sigaction(SIGSEGV, &handler, &old_handler) < 0) {
        perror("Eroare sigaction\n");
        exit(EXIT_FAILURE);
    }
 
    pageSize = getpagesize();
    handler.sa_flags = SA_SIGINFO;
    return 0;
}
 
int so_execute(char *path, char *argv[])
{
    exec = so_parse_exec(path);
    if (!exec) {
        perror("Eroare so_parse_exec!\n");
        exit(EXIT_FAILURE);
    }
 	
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("Eroare deschidere fisier!\n");
        exit(EXIT_FAILURE);
    }
 
    int cnt = 0;
    /*initializez structura de evidenta a paginilor*/
    while (cnt < exec->segments_no) {
        
        exec->segments[cnt].data =
                malloc(sizeof(struct pageEvidence));
        
        if (!exec->segments[cnt].data) {
            perror("Eroare alocare memorie segment data!\n");
            exit(EXIT_FAILURE);
        }
 
        cnt ++;
    }
 
    so_start_exec(exec, argv);
 
    return 0;
}
