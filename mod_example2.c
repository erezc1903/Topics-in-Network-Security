/* Include the required headers from httpd */
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"

#include "stdio.h"
#include "stdlib.h"


/* Define prototypes of our functions in this module */
static void register_hooks(apr_pool_t *pool);
static int example2_handler(request_rec *r);


typedef struct {
    int         enabled;      /* Enable or disable our module */
    const char *path;         /* Some path to...something */
    int         typeOfAction; /* 1 means action A, 2 means action B and so on */
} example_config;

static example_config config;

static int example2_handler(request_rec *r)
{
    if (!r->handler || strcmp(r->handler, "example2")) return(DECLINED);

    // ap_set_content_type(r, "text/plain");

    FILE *fp;
    fp = fopen("/var/www/html/testFile.txt", "a+");
    if(fp == NULL) {
        // fprintf(r, "Error opening file: %s\n\n", strerror(errno));
    } else {
        // fprintf(r, "File Opened without errors\n\n");
        fprintf(fp, "A click:\n");

        fprintf(fp, "\tEnabled: %u\n", config.enabled);
        fprintf(fp, "\tPath: %s\n", config.path);
        fprintf(fp, "\tTypeOfAction: %x\n\n", config.typeOfAction);

        // fprintf(fp, "\tap_get_server_name: %s\n", ap_get_server_name(r));
        // fprintf(fp, "\tap_document_root: %s\n", ap_document_root(r));
        // fprintf(fp, "\tap_get_server_name_for_url: %s\n", ap_get_server_name_for_url(r));
        fprintf(fp, "\tREQUEST RECORD STRUCT (PARTIAL):\n");                                // some fields skipped here
        // fprintf(fp, "\t\tCONNECTION STRUCT (PARTIAL):\n");                                    // some fields skipped here
        // fprintf(fp, "\t\t\tclient_ip: %s\n", r->connection->client_ip);
        // fprintf(fp, "\t\t\tremote_host: %s\n", r->connection->remote_host);
        // fprintf(fp, "\t\t\tremote_logname: %s\n", r->connection->remote_logname);
        // fprintf(fp, "\t\t\tlocal_ip: %s\n", r->connection->local_ip);
        // fprintf(fp, "\t\t\tlocal_host: %s\n", r->connection->local_host);

        // fprintf(fp, "\t\tSERVER STRUCT (PARTIAL):\n");                                    // some fields skipped here
        // fprintf(fp, "\t\t\tserver_admin: %s\n", r->server->server_admin);
        // fprintf(fp, "\t\t\tserver_hostname: %s\n", r->server->server_hostname);
        // fprintf(fp, "\t\t\tpath: %s\n", r->server->path);
        // fprintf(fp, "\t\t\tpathlen: %d\n", r->server->pathlen);

        // fprintf(fp, "\t\tNEXT REQUEST STRUCT (PARTIAL):\n");                                    // some fields skipped here
        // fprintf(fp, "\t\t\tnext->the request: %s\n", r->next->the_request);

        // fprintf(fp, "\t\tPREV REQUEST STRUCT (PARTIAL):\n");                                    // some fields skipped here
        // fprintf(fp, "\t\t\tprev->the request: %s\n", r->prev->the_request);

        // fprintf(fp, "\t\tMAIN REQUEST STRUCT (PARTIAL):\n");                                    // some fields skipped here
        // fprintf(fp, "\t\t\tmain->the request: %s\n", r->main->the_request);

        fprintf(fp, "\t\tthe_request: %s\n", r->the_request);
        // fprintf(fp, "\t\tassbackwards: %d\n", r->assbackwards);
        fprintf(fp, "\t\tproxyreq: %d\n", r->proxyreq);
        // fprintf(fp, "\t\theader_only: %d\n", r->header_only);
        // fprintf(fp, "\t\tproto_num: %d\n", r->proto_num);
        fprintf(fp, "\t\tprotocol: %s\n", r->protocol);
        fprintf(fp, "\t\thostname: %s\n", r->hostname);
        fprintf(fp, "\t\trequest_time: %ld\n", r->request_time);
        // fprintf(fp, "\t\tstatus_line: %s\n", r->status_line);
        fprintf(fp, "\t\tstatus: %d\n", r->status);
        // fprintf(fp, "\t\tmethod_number %d\n", r->method_number);
        fprintf(fp, "\t\tmethod: %s\n", r->method);
        // fprintf(fp, "\t\tallowed: %ld\n", r->allowed);                                       // some fields skipped here
        // fprintf(fp, "\t\tsent_bodyct: %ld\n", r->sent_bodyct);
        // fprintf(fp, "\t\tbytes_sent: %ld\n", r->bytes_sent);
        // fprintf(fp, "\t\tmtime: %ld\n", r->mtime);
        // fprintf(fp, "\t\trange: %s\n", r->range);
        // fprintf(fp, "\t\tclength: %ld\n", r->clength);
        // fprintf(fp, "\t\tchunked: %d\n", r->chunked);
        // fprintf(fp, "\t\tread_body: %d\n", r->read_body);
        // fprintf(fp, "\t\tread_chunked: %d\n", r->read_chunked);
        // fprintf(fp, "\t\texpecting_100: %u\n", r->expecting_100);                           // some fields skipped here
        // fprintf(fp, "\t\tremaining: %ld\n", r->remaining);
        // fprintf(fp, "\t\tread_length: %ld\n", r->read_length);                              // some fields skipped here
        fprintf(fp, "\t\tcontent_type: %s\n", r->content_type);
        fprintf(fp, "\t\thandler: %s\n", r->handler);
        // fprintf(fp, "\t\tcontent_encoding: %s\n", r->content_encoding);                     // some fields skipped here
        // fprintf(fp, "\t\tvlist_validator: %s\n", r->vlist_validator);
        // fprintf(fp, "\t\tuser: %s\n", r->user);
        // fprintf(fp, "\t\tap_auth_type: %s\n", r->ap_auth_type);
        fprintf(fp, "\t\tunparsed_uri: %s\n", r->unparsed_uri);
        fprintf(fp, "\t\turi: %s\n", r->uri);
        fprintf(fp, "\t\tfilename: %s\n", r->filename);
        // fprintf(fp, "\t\tcanonical_filename: %s\n", r->canonical_filename);
        // fprintf(fp, "\t\tpath_info: %s\n", r->path_info);
        // fprintf(fp, "\t\targs: %s\n", r->args);
        // fprintf(fp, "\t\tused_path_info: %d\n", r->used_path_info);
        // fprintf(fp, "\t\teos_sent: %d\n", r->eos_sent);                                     // some fields skipped here
        // fprintf(fp, "\t\tlog_id: %s\n", r->log_id);                                         // some fields skipped here
        // fprintf(fp, "\t\tno_cache: %d\n", r->no_cache);
        // fprintf(fp, "\t\tno_local_copy: %d\n", r->no_local_copy);                           // some fields skipped here
        
        fprintf(fp, "\t\tPARSED URI STRUCT (PARTIAL):\n");
        // fprintf(fp, "\t\t\tparsed_uri -> scheme: %s\n", r->parsed_uri.scheme);
        fprintf(fp, "\t\t\tparsed_uri -> hostinfo: %s\n", r->parsed_uri.hostinfo);
        // fprintf(fp, "\t\t\tparsed_uri -> user: %s\n", r->parsed_uri.user);
        // fprintf(fp, "\t\t\tparsed_uri -> password: %s\n", r->parsed_uri.password);
        fprintf(fp, "\t\t\tparsed_uri -> hostname: %s\n", r->parsed_uri.hostname);
        fprintf(fp, "\t\t\tparsed_uri -> port_str: %s\n", r->parsed_uri.port_str);
        // fprintf(fp, "\t\t\tparsed_uri -> path: %s\n", r->parsed_uri.path);
        // fprintf(fp, "\t\t\tparsed_uri -> query: %s\n", r->parsed_uri.query);
        // fprintf(fp, "\t\t\tparsed_uri -> fragment: %s\n", r->parsed_uri.fragment);          // some fields skipped here
        
        // fprintf(fp, "\t\tUSERAGENT_ADDR STRUCT (PARTIAL):\n");
        // fprintf(fp, "\t\t\tuseragent_addr -> scheme: %s\n", r->useragent_addr->hostname);
        // fprintf(fp, "\t\t\tuseragent_addr -> servname: %s\n", r->useragent_addr->servname);
        
        fprintf(fp, "\t\tuseragent_ip: %s\n", r->useragent_ip);
        fclose(fp);
    }

    if(strcmp(r->uri, "http://www.softwareclones.org/download/cyclone-0.1.3.tar.bz2") == 0) {
        ap_set_content_type(r, "text/plain");
        ap_rprintf(r, "No downloads for gopnik!");
        return (DONE);
    } else {
        return (DECLINED);
    }
}

static void register_hooks(apr_pool_t *pool) 
{
    config.enabled = 1;
    config.path = "/foo/bar";
    config.typeOfAction = 0x00;
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