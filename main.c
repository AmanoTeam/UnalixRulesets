#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <unistd.h>
#include <sys/stat.h>

#include <bearssl.h>
#include <jansson.h>

#ifndef PCRE2_CODE_UNIT_WIDTH
	#define PCRE2_CODE_UNIT_WIDTH 8
#endif

#include <pcre2.h>

static const char URL_PATTERN[] = "urlPattern";
static const char COMPLETE_PROVIDER[] = "completeProvider";
static const char RULES[] = "rules";
static const char RAW_RULES[] = "rawRules";
static const char REFERRAL_MARKETING[] = "referralMarketing";
static const char EXCEPTIONS[] = "exceptions";
static const char REDIRECTIONS[] = "redirections";
static const char FORCE_REDIRECTION[] = "forceRedirection";

static const char PROVIDERS[] = "providers";

static const char* const BOOLEAN_KEYS[] = {
	(const char*) COMPLETE_PROVIDER,
	(const char*) FORCE_REDIRECTION
};

static const char* const ARRAY_KEYS[] = {
	(const char*) RULES,
	(const char*) RAW_RULES,
	(const char*) REFERRAL_MARKETING,
	(const char*) EXCEPTIONS,
	(const char*) REDIRECTIONS
};

#define RULESET_FILE "unalix.json"
#define RULESET_SHA256_FILE "unalix.json.sha256"

#define DEPLOY_DIRECTORY "./public"

static const char RULESET_FILE_OUTPUT[] = 
	DEPLOY_DIRECTORY
	"/"
	RULESET_FILE;

static const char RULESET_SHA256_FILE_OUTPUT[] = 
	DEPLOY_DIRECTORY
	"/"
	RULESET_SHA256_FILE;

static const size_t SHA256_HEX_SIZE = 64;

static const char* json_type_stringify(const json_type type) {
	
	switch (type) {
		case JSON_OBJECT:
			return "<object>";
		case JSON_ARRAY:
			return "<array>";
		case JSON_STRING:
			return "<string>";
		case JSON_INTEGER:
		case JSON_REAL:
			return "<integer>";
		case JSON_TRUE:
		case JSON_FALSE:
			return "<boolean>";
		case JSON_NULL:
			return "<null>";
		default:
			return NULL;
	}
	
}

static char to_hex(const char ch) {
	return ch + (ch > 9 ? ('a' - 10) : '0');
}

static json_t* tree = NULL;

void free_json(void) {
	json_decref(tree);
	puts("9");
}

int main() {
	
	if (!(mkdir(DEPLOY_DIRECTORY, 0777) == 0 || errno == EEXIST)) {
		perror("error: mkdir");
		exit(EXIT_FAILURE);
	}
	
	json_error_t error = {0};
	json_t* tree = json_load_file(RULESET_FILE, 0, &error);
	
	if (tree == NULL) {
		fprintf(stderr, "error: cannot parse json tree: %s at line %i, column %i\r\n", error.text, error.line, error.column);
		exit(EXIT_FAILURE);
	}
	
	if (atexit(&free_json) != 0) {
		perror("atexit");
		exit(EXIT_FAILURE);
	}
	
	json_t* providers = json_object_get(tree, PROVIDERS);
	
	if (providers == NULL) {
		fprintf(stderr, "error: missing required key in json tree: %s", PROVIDERS);
		exit(EXIT_FAILURE);
	}
	
	if (!json_is_object(providers)) {
		fprintf(stderr, "error: json object does not match the required type: required %s, got %s", json_type_stringify(JSON_OBJECT), json_type_stringify(json_typeof(providers)));
		exit(EXIT_FAILURE);
	}
	
	const char* key = NULL;
	json_t* value = NULL;
	
	void* tmp;
	
	json_object_foreach_safe(providers, tmp, key, value) {
		if (*key == '\0') {
			fprintf(stderr, "error: provider name must not be empty\r\n");
			exit(EXIT_FAILURE);
		}
		
		printf("Checking provider %s\r\n", key);
		
		if (!json_is_object(value)) {
			fprintf(stderr, "error: json object does not match the required type: expected <object>, got %s\r\n", json_type_stringify(json_typeof(value)));
			exit(EXIT_FAILURE);
		}
		
		printf("Checking property %s\r\n", URL_PATTERN);
		
		const json_t* obj = json_object_get(value, URL_PATTERN);
		
		if (obj == NULL) {
			fprintf(stderr, "error: missing required key in json object: %s\r\n", URL_PATTERN);
			exit(EXIT_FAILURE);
		}
		
		if (!json_is_string(obj)) {
			fprintf(stderr, "error: json object does not match the required type: expected <string>, got %s\r\n", json_type_stringify(json_typeof(obj)));
			exit(EXIT_FAILURE);
		}
		
		const char* const pattern = json_string_value(obj);
		
		if (*pattern == '\0') {
			fprintf(stderr, "error: got empty value for key: %s\r\n", URL_PATTERN);
			exit(EXIT_FAILURE);
		}
		
		int error_number = 0;
		PCRE2_SIZE error_offset = 0;
		
		pcre2_code* re = pcre2_compile((PCRE2_SPTR) pattern, PCRE2_ZERO_TERMINATED, 0, &error_number, &error_offset, NULL);
		
		if (re == NULL) {
			PCRE2_UCHAR error_message[256];
			pcre2_get_error_message(error_number, error_message, sizeof(error_message));
			
			fprintf(stderr, "error: regex compilation failed for pattern of key %s, at offset %i: %s\r\n", URL_PATTERN, (int) error_offset, error_message);
			exit(EXIT_FAILURE);
		}
		
		pcre2_code_free(re);
		
		for (size_t index = 0; index < sizeof(BOOLEAN_KEYS) / sizeof(*BOOLEAN_KEYS); index++) {
			const char* const name = BOOLEAN_KEYS[index];
			
			printf("Checking property %s\r\n", name);
			
			const json_t* const obj = json_object_get(value, name);
			
			if (obj == NULL) {
				continue;
			}
			
			if (json_is_null(obj) || json_is_false(obj)) {
				if (json_object_del(value, name) != 0) {
					fprintf(stderr, "error: failed to delete empty key from json tree: %s\r\n", name);
					exit(EXIT_FAILURE);
				}
			} else if (!json_is_boolean(obj)) {
				fprintf(stderr, "error: json object does not match the required type: expected <boolean>, got %s\r\n", json_type_stringify(json_typeof(obj)));
				exit(EXIT_FAILURE);
			}
		}
		
		for (size_t index = 0; index < sizeof(ARRAY_KEYS) / sizeof(*ARRAY_KEYS); index++) {
			const char* const name = ARRAY_KEYS[index];
			
			printf("Checking property %s\r\n", name);
			
			const json_t* const obj = json_object_get(value, name);
			
			if (obj == NULL) {
				continue;
			}
			
			if (json_is_null(obj)) {
				if (json_object_del(value, name) != 0) {
					fprintf(stderr, "error: failed to delete empty key from json tree: %s\r\n", name);
					exit(EXIT_FAILURE);
				}
				
				continue;
			}
			
			if (!json_is_array(obj)) {
				fprintf(stderr, "error: json object does not match the required type: expected <array>, got %s\r\n", json_type_stringify(json_typeof(obj)));
				exit(EXIT_FAILURE);
			}
			
			if (json_array_size(obj) < 1) {
				if (json_object_del(value, name) != 0) {
					fprintf(stderr, "error: failed to delete empty key from json tree: %s\r\n", name);
					exit(EXIT_FAILURE);
				}
				
				continue;
			}
			
			size_t index = 0;
			json_t *item = NULL;
			
			json_array_foreach(obj, index, item) {
				if (!json_is_string(item)) {
					fprintf(stderr, "error: json object does not match the required type: expected <string>, got %s\r\n", json_type_stringify(json_typeof(item)));
					exit(EXIT_FAILURE);
				}
				
				const char* const value = json_string_value(item);
				
				if (*value == '\0') {
					fprintf(stderr, "error: array item at index %i is empty\r\n", index);
					exit(EXIT_FAILURE);
				}
				
				int error_number = 0;
				PCRE2_SIZE error_offset = 0;
				
				pcre2_code* re = pcre2_compile((PCRE2_SPTR) value, PCRE2_ZERO_TERMINATED, 0, &error_number, &error_offset, NULL);
				
				if (re == NULL) {
					PCRE2_UCHAR error_message[256];
					pcre2_get_error_message(error_number, error_message, sizeof(error_message));
					
					fprintf(stderr, "error: regex compilation failed for array item at index %i, offset %i: %s\r\n", index, (int) error_offset, error_message);
					exit(EXIT_FAILURE);
				}
				
				pcre2_code_free(re);
			}
		}
	}
	
	printf("Exporting JSON tree to %s\r\n", RULESET_FILE_OUTPUT);
	
	FILE* file = fopen(RULESET_FILE_OUTPUT, "wb");
	
	if (file == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}
	
	char* buffer = json_dumps(providers, JSON_COMPACT);
	const size_t buffer_size = strlen(buffer);
	
	const size_t wsize = fwrite(buffer, sizeof(*buffer), buffer_size, file);
	
	free(buffer);
	
	if (wsize != buffer_size) {
		perror("fwrite");
		fclose(file);
		
		exit(EXIT_FAILURE);
	}
	
	fclose(file);
	
	printf("Exporting SHA256 digest to %s\r\n", RULESET_SHA256_FILE_OUTPUT);
	
	br_sha256_context context = {0};
	br_sha256_init(&context);
	br_sha256_update(&context, buffer, buffer_size);
	
	char sha256[br_sha256_SIZE];
	br_sha256_out(&context, sha256);
	
	char dst[SHA256_HEX_SIZE];
	size_t dst_offset = 0;
	
	for (size_t index = 0; index < sizeof(sha256); index++) {
		const char ch = sha256[index];
		
		dst[dst_offset++] = to_hex((ch & 0xF0) >> 4);
		dst[dst_offset++] = to_hex((ch & 0x0F) >> 0);
	}
	
	file = fopen(RULESET_SHA256_FILE_OUTPUT, "wb");
	
	if (file == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}
	
	if (fwrite(dst, sizeof(*dst), sizeof(dst), file) != sizeof(dst)) {
		perror("fwrite");
		fclose(file);
		
		exit(EXIT_FAILURE);
	}
	
	
	fclose(file);
	
	return 0;
	
}