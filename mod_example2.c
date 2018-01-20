/* Include the required headers from httpd */
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"

#include "stdio.h"
#include "stdlib.h"
#include "string.h"



/* Define prototypes of our functions in this module */
static void register_hooks(apr_pool_t *pool);
static int example2_handler(request_rec *r);
static char* virusName(char* str);
static char* initVirusList();



/* Define the virus list */
static char *virusList;



/* Our handler function. receives a request record r, handles it. */
static int example2_handler(request_rec *r)
{
    if (!r->handler || strcmp(r->handler, "example2")) return(DECLINED);
    FILE *fp;
    fp = fopen("/var/www/html/testFile.txt", "a+");
    if(fp == NULL) {
        // do nothing
    } else {
        fprintf(fp, "A click:\n");
        fprintf(fp, "\tREQUEST RECORD STRUCT (PARTIAL):\n");
        fprintf(fp, "\t\tthe_request: %s\n", r->the_request);
        fprintf(fp, "\t\tprotocol: %s\n", r->protocol);
        fprintf(fp, "\t\thostname: %s\n", r->hostname);
        fprintf(fp, "\t\trequest_time: %ld\n", r->request_time);
        fprintf(fp, "\t\tstatus: %d\n", r->status);
        fprintf(fp, "\t\tmethod: %s\n", r->method);
        fprintf(fp, "\t\tcontent_type: %s\n", r->content_type);
        fprintf(fp, "\t\thandler: %s\n", r->handler);
        fprintf(fp, "\t\tunparsed_uri: %s\n", r->unparsed_uri);
        fprintf(fp, "\t\turi: %s\n", r->uri);
        fprintf(fp, "\t\tfilename: %s\n", r->filename);
        fprintf(fp, "\t\tuseragent_ip: %s\n", r->useragent_ip);
    }

    /* For debugging purposes */
    // FILE *virusTest;
    // virusTest = fopen("/var/www/html/virusTest.txt", "a+");

    // char* virus = virusName(r->uri);
    // fprintf(virusTest, "\t\tvirus: %s\n", virus);
    // fprintf(virusTest, "\t\turi: %s\n\n", r->uri);
    // fclose(virusTest);

    if( (virusName(r->uri) != NULL) && (strstr(virusList, virusName(r->uri)) != NULL)) {
        ap_set_content_type(r, "text/html");
        ap_rprintf(r, "<HTML><HEAD><TITLE>Virus Download Detected</TITLE></HEAD><BODY><H1>This file is a virus. please click on the following link to be redirected to a safe place.</H1><a href=\"http://www.google.com\">Link Name</a></BODY></HTML> ");
        fprintf(fp, "\t\t=============================VIRUS DETECTED!!==========================\n\n");
        fclose(fp);
        return (DONE);
    } else {
        fprintf(fp, "\n");
        fclose(fp);
        return (DECLINED);
    }
}



/* The function that registers our handler */
static void register_hooks(apr_pool_t *pool) 
{
    virusList = initVirusList();
    ap_hook_handler(example2_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}



/* Define our module as an entity and assign a function for registering hooks  */
module AP_MODULE_DECLARE_DATA   example2_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,            /* Per-directory configuration handler */
    NULL,            /* Merge handler for per-directory configurations */
    NULL,            /* Per-server configuration handler */
    NULL,            /* Merge handler for per-server configurations */
    NULL,            /* Any directives we may have for httpd */
    register_hooks   /* Our hook registering function */
};



/* This function receives a url and extracts the file name from it, if any.
   If there isnt any file, returns NULL */
static char* virusName(char* str){

    char *temp = malloc(strlen(str));
    strcpy(temp, str);
    int slashCounter = 0;

    for (int i=0; i<strlen(temp); i++){
            if(temp[i] == '/'){
                slashCounter++;
            }
        }

    int i = 0;
    char *strTokens  = strtok(temp, "/");
    char *tokensArray[slashCounter+1];

    while(strTokens != NULL){
        tokensArray[i++] = strTokens;
        strTokens = strtok(NULL,  "/");
    }

    return tokensArray[slashCounter-1];
}



/* Initializes the virus list from a file */
static char* initVirusList(){

    FILE *BlackList;
    BlackList = fopen("/var/www/html/BlackList.txt", "r+");

    fseek(BlackList, 0, SEEK_END);
    long fsize = ftell(BlackList);
    fseek(BlackList, 0, SEEK_SET);  //same as rewind(f);

    char *virusList = malloc(fsize + 1);
    size_t numberOfItemsRead = fread(virusList, fsize, 1, BlackList);
    fclose(BlackList);

    return virusList;
}
