#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <curl/curl.h>

#define CACERT_PATH "/etc/drohn/certs/cacert.pem"
#define CERT_PATH "/etc/drohn/certs/wildcat_router.crt"
#define KEY_PATH "/etc/drohn/private/wildcat_router.key"

static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t retcode;
  
	retcode = fread(ptr, size, nmemb, stream);
	return retcode;
}

int main(int argc, char **argv)
{
	CURL *curl;
	CURLcode res;
	FILE * hd_src ;
	struct stat file_info;
	int ret;
	char *file;
	char *url;

	if(argc < 3)
		return 1;
 
	file= argv[1];
	url = argv[2];
 
	/* get the file size of the local file */ 
	stat(file, &file_info);

	/* get a FILE * of the same file, could also be made with
		fdopen() from the previous descriptor, but hey this is just
		an example! */ 
	hd_src = fopen(file, "rb");
 
	/* In windows, this will init the winsock stuff */ 
	curl_global_init(CURL_GLOBAL_ALL);
 
	/* get a curl handle */ 
	curl = curl_easy_init();
	if(curl) {
		/* we want to use our own read function */ 
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);

		/* set client cert */
		curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
		curl_easy_setopt(curl, CURLOPT_SSLCERT, CERT_PATH);
		/* set client key */
		curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
		curl_easy_setopt(curl, CURLOPT_SSLKEY, KEY_PATH);

		/* set CA path */
		curl_easy_setopt(curl, CURLOPT_CAPATH, CACERT_PATH);
		curl_easy_setopt(curl, CURLOPT_CAINFO, CACERT_PATH);

		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

		/* enable uploading */ 
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
 
		/* HTTP PUT please */ 
 		curl_easy_setopt(curl, CURLOPT_PUT, 1L);
 
		/* specify target URL, and note that this URL should include a file
			name, not only a directory */ 
		curl_easy_setopt(curl, CURLOPT_URL, url);
 
		/* now specify which file to upload */ 
		curl_easy_setopt(curl, CURLOPT_READDATA, hd_src);
 
		/* provide the size of the upload, we specicially typecast the value
			to curl_off_t since we must be sure to use the correct data size */ 
		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
							(curl_off_t)file_info.st_size);
 
		/* Now run off and do what you've been told! */ 
		res = curl_easy_perform(curl);
		/* Check for errors */ 
		if(res != CURLE_OK){
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
					curl_easy_strerror(res));
		}
 
		/* always cleanup */ 
		curl_easy_cleanup(curl);
	}
	fclose(hd_src); /* close the local file */ 

	curl_global_cleanup();

	if(res == CURLE_OK){
		if((ret=remove(file)) != 0){
			fprintf(stderr, "curlput failed to remove file: %s\n", file);
		}
	}
	return 0;
}
