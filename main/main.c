/* Simple HTTP Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

// Server HTTP includes

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_eth.h"
#include "protocol_examples_common.h"
#include "esp_tls_crypto.h"
#include <esp_http_server.h>


// SPI includes


#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"

#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"
#include "lwip/igmp.h"

#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "soc/rtc_periph.h"
#include "driver/spi_master.h"
#include "esp_log.h"
#include "esp_spi_flash.h"

#include "driver/gpio.h"
#include "esp_intr_alloc.h"


// Client HTTP includes
#include "stdio.h"
#include "string.h"

#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "esp_tls.h"


#include "esp_http_client.h"
#include "esp_netif_ip_addr.h"
#include "esp_mac.h"
#include "mdns.h"
#include "driver/gpio.h"
#include "netdb.h"

#define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 2048
//static const char *TAG = "HTTP_CLIENT";


#if CONFIG_IDF_TARGET_ESP32 || CONFIG_IDF_TARGET_ESP32S2
#define GPIO_HANDSHAKE 2
#define GPIO_MOSI 12
#define GPIO_MISO 13
#define GPIO_SCLK 15
#define GPIO_CS 14

#elif CONFIG_IDF_TARGET_ESP32C3
#define GPIO_HANDSHAKE 3
#define GPIO_MOSI 7
#define GPIO_MISO 2
#define GPIO_SCLK 6
#define GPIO_CS 10


#endif //CONFIG_IDF_TARGET_ESP32 || CONFIG_IDF_TARGET_ESP32S2


#ifdef CONFIG_IDF_TARGET_ESP32
#define SENDER_HOST HSPI_HOST

#elif defined CONFIG_IDF_TARGET_ESP32S2
#define SENDER_HOST SPI2_HOST

#elif defined CONFIG_IDF_TARGET_ESP32C3
#define SENDER_HOST SPI2_HOST

#endif

#ifdef CONFIG_IDF_TARGET_ESP32
#define SENDER_HOST HSPI_HOST

#elif defined CONFIG_IDF_TARGET_ESP32S2
#define SENDER_HOST SPI2_HOST

#elif defined CONFIG_IDF_TARGET_ESP32C3
#define SENDER_HOST SPI2_HOST

#endif

// ############  Cube configs  ##################
#define NUM_SHIFT_REGISTERS 12
#define MAX_CITY_NAME_SIZE 32
// ############ Globl Variables #################

esp_err_t ret;
spi_device_handle_t handle;
int weather_update_countdown = 0;
char cube[512] = {0};
char city_for_weaher[MAX_CITY_NAME_SIZE];
char weather_requests_are_enabled = true;

/* A simple example that demonstrates how to create GET and POST
 * handlers for the web server.
 */

static const char *TAG = "example";

#if CONFIG_EXAMPLE_BASIC_AUTH

typedef struct {
    char    *username;
    char    *password;
} basic_auth_info_t;

#define HTTPD_401      "401 UNAUTHORIZED"           /*!< HTTP Response 401 */

static char *http_auth_basic(const char *username, const char *password)
{
    int out;
    char *user_info = NULL;
    char *digest = NULL;
    size_t n = 0;
    asprintf(&user_info, "%s:%s", username, password);
    if (!user_info) {
        ESP_LOGE(TAG, "No enough memory for user information");
        return NULL;
    }
    esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *)user_info, strlen(user_info));

    /* 6: The length of the "Basic " string
     * n: Number of bytes for a base64 encode format
     * 1: Number of bytes for a reserved which be used to fill zero
    */
    digest = calloc(1, 6 + n + 1);
    if (digest) {
        strcpy(digest, "Basic ");
        esp_crypto_base64_encode((unsigned char *)digest + 6, n, (size_t *)&out, (const unsigned char *)user_info, strlen(user_info));
    }
    free(user_info);
    return digest;
}

/* An HTTP GET handler */
static esp_err_t basic_auth_get_handler(httpd_req_t *req)
{
    char *buf = NULL;
    size_t buf_len = 0;
    basic_auth_info_t *basic_auth_info = req->user_ctx;

    buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
    if (buf_len > 1) {
        buf = calloc(1, buf_len);
        if (!buf) {
            ESP_LOGE(TAG, "No enough memory for basic authorization");
            return ESP_ERR_NO_MEM;
        }

        if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
        } else {
            ESP_LOGE(TAG, "No auth value received");
        }

        char *auth_credentials = http_auth_basic(basic_auth_info->username, basic_auth_info->password);
        if (!auth_credentials) {
            ESP_LOGE(TAG, "No enough memory for basic authorization credentials");
            free(buf);
            return ESP_ERR_NO_MEM;
        }

        if (strncmp(auth_credentials, buf, buf_len)) {
            ESP_LOGE(TAG, "Not authenticated");
            httpd_resp_set_status(req, HTTPD_401);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
            httpd_resp_send(req, NULL, 0);
        } else {
            ESP_LOGI(TAG, "Authenticated!");
            char *basic_auth_resp = NULL;
            httpd_resp_set_status(req, HTTPD_200);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            asprintf(&basic_auth_resp, "{\"authenticated\": true,\"user\": \"%s\"}", basic_auth_info->username);
            if (!basic_auth_resp) {
                ESP_LOGE(TAG, "No enough memory for basic authorization response");
                free(auth_credentials);
                free(buf);
                return ESP_ERR_NO_MEM;
            }
            httpd_resp_send(req, basic_auth_resp, strlen(basic_auth_resp));
            free(basic_auth_resp);
        }
        free(auth_credentials);
        free(buf);
    } else {
        ESP_LOGE(TAG, "No auth header received");
        httpd_resp_set_status(req, HTTPD_401);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "keep-alive");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
        httpd_resp_send(req, NULL, 0);
    }

    return ESP_OK;
}

static httpd_uri_t basic_auth = {
    .uri       = "/basic_auth",
    .method    = HTTP_GET,
    .handler   = basic_auth_get_handler,
};

static void httpd_register_basic_auth(httpd_handle_t server)
{
    basic_auth_info_t *basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
    if (basic_auth_info) {
        basic_auth_info->username = CONFIG_EXAMPLE_BASIC_AUTH_USERNAME;
        basic_auth_info->password = CONFIG_EXAMPLE_BASIC_AUTH_PASSWORD;

        basic_auth.user_ctx = basic_auth_info;
        httpd_register_uri_handler(server, &basic_auth);
    }
}
#endif

void string_param_to_SPI_char(char param[], char led_states[]){
    for(int i = 0; i < 128; i++) {
        char four_led_state = param[i] - '0';
        if (four_led_state > 9) {
            four_led_state -= ('a' - '0'- 10);

        }
        //printf(" %d", four_led_state);

        // Добавить обработку ошибок !!! 
        led_states[i * 4 + 3] = four_led_state & 0x1;
        led_states[i * 4 + 2] = (four_led_state & 0x2) >> 1;
        led_states[i * 4 + 1] = (four_led_state & 0x4) >> 2;
        led_states[i * 4 + 0] = (four_led_state & 0x8) >> 3;        
    }
}

/* An HTTP GET handler */
static esp_err_t cube_get_handler(httpd_req_t *req)
{
    char*  buf;
    size_t buf_len;


    /* Read URL query string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
            weather_requests_are_enabled = false;

            ESP_LOGI(TAG, "Found URL query => %s", buf);
            const int hex_data_size = 200;
            char param[hex_data_size];
            /* Get value of expected key from query string */
            if (httpd_query_key_value(buf, "query1", param, hex_data_size) == ESP_OK) {
                string_param_to_SPI_char(param, cube);   
                ESP_LOGI(TAG, "Remade query to bin format=%s", cube);
                ESP_LOGI(TAG, "Found URL query parameter => query1=%s", param);

            }
            
        }

        free(buf);
    }


  
    /* Send response with custom headers and body set as the
     * string passed in user context*/
    const char* resp_str = (const char*) req->user_ctx;
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
        ESP_LOGI(TAG, "Request headers lost");
    }
    return ESP_OK;
}

static const httpd_uri_t cube_http = {
    .uri       = "/cube",
    .method    = HTTP_GET,
    .handler   = cube_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = "Cube accepted"
};

static esp_err_t  location_get_handler(httpd_req_t *req)
{
    char*  buf;
    size_t buf_len;



    /* Read URL query string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query => %s", buf);
            /* Get value of expected key from query string */
            if (httpd_query_key_value(buf, "region", city_for_weaher, MAX_CITY_NAME_SIZE) == ESP_OK) {
                ESP_LOGI(TAG, "Got city=%s", city_for_weaher);
                weather_requests_are_enabled = true;
                weather_update_countdown = 0;
            }
            
        }

        free(buf);
    }


  
    /* Send response with custom headers and body set as the
     * string passed in user context*/
    const char* resp_str = (const char*) req->user_ctx;
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
        ESP_LOGI(TAG, "Request headers lost");
    }
    return ESP_OK;
}

static const httpd_uri_t location = {
    .uri       = "/location",
    .method    = HTTP_GET,
    .handler   = location_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = "location accepted"
};


/* This handler allows the custom error handling functionality to be
 * tested from client side. For that, when a PUT request 0 is sent to
 * URI /ctrl, the /hello and /echo URIs are unregistered and following
 * custom error handler http_404_error_handler() is registered.
 * Afterwards, when /hello or /echo is requested, this custom error
 * handler is invoked which, after sending an error message to client,
 * either closes the underlying socket (when requested URI is /echo)
 * or keeps it open (when requested URI is /hello). This allows the
 * client to infer if the custom error handler is functioning as expected
 * by observing the socket state.
 */
esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (strcmp("/cube", req->uri) == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/cube URI is not available");
        /* Return ESP_OK to keep underlying socket open */
        return ESP_OK;
    }
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}





static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    // config.server_port = 90;
    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &cube_http);
        httpd_register_uri_handler(server, &location);
        // httpd_register_uri_handler(server, &ctrl);
        #if CONFIG_EXAMPLE_BASIC_AUTH
        httpd_register_basic_auth(server);
        #endif
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

static esp_err_t stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_stop(server);
}

static void disconnect_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server) {
        ESP_LOGI(TAG, "Stopping webserver");
        if (stop_webserver(*server) == ESP_OK) {
            *server = NULL;
        } else {
            ESP_LOGE(TAG, "Failed to stop http server");
        }
    }
}

static void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server == NULL) {
        ESP_LOGI(TAG, "Starting webserver");
        *server = start_webserver();
    }
}

static void IRAM_ATTR gpio_handshake_isr_handler(void* arg)
{
    // //Sometimes due to interference or ringing or something, we get two irqs after eachother. This is solved by
    // //looking at the time between interrupts and refusing any interrupt too close to another one.
    // static uint32_t lasthandshaketime;
    // uint32_t currtime=esp_cpu_get_ccount();
    // uint32_t diff=currtime-lasthandshaketime;
    // if (diff<240000) return; //ignore everything <1ms after an earlier irq
    // lasthandshaketime=currtime;

    // //Give the semaphore.
    // BaseType_t mustYield=false;
    // xSemaphoreGiveFromISR(rdySem, &mustYield);
    // if (mustYield) portYIELD_FROM_ISR();
}

TaskHandle_t WebServerTaskHandle = NULL;
TaskHandle_t SPITaskHandle = NULL;
TaskHandle_t WeatherClientTaskHandle = NULL;

void web_server_Task(void *arg)
{
    static httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    /* Register event handlers to stop the server when Wi-Fi or Ethernet is disconnected,
     * and re-start it upon connection.
     */
#ifdef CONFIG_EXAMPLE_CONNECT_WIFI
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_WIFI
#ifdef CONFIG_EXAMPLE_CONNECT_ETHERNET
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_ETHERNET

    /* Start the server for the first time */
    server = start_webserver();
    while(1) {
        vTaskDelay(1000);
    }
}


// API Client



void get_str_value(
    const char * json_string,
    const char * param_name,
    char * output_value_string
) {
    int start_pos = 0;
    int end_pos = 0;

    start_pos = (int)(strstr(json_string, param_name) - json_string);
    start_pos += strlen(param_name) + 2; // +2 for ":
    end_pos = (int)(strpbrk(&json_string[start_pos], ",}") - json_string);
    
    int substring_size = end_pos - start_pos;
    memcpy(output_value_string, &json_string[start_pos], substring_size);
    output_value_string[substring_size] = '\0';
}


// char num2_[] = "00000000000000000000000000000000000000700000000000000040000000000000002000000000000000100000000000000070000000000000000000000000";
// char num_2[] = "00000000000000000000000000000000000000070000000000000004000000000000000200000000000000010000000000000007000000000000000000000000";
// char num1_[] = "00000000000000000000000000000000000000700000000000000020000000000000002000000000000000600000000000000020000000000000000000000000";
// char num_1[] = "00000000000000000000000000000000000000070000000000000002000000000000000200000000000000060000000000000002000000000000000000000000";
// char minus[] = "00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000";
// char num3_[] = "00000000000000000000000000000000000000600000000000000010000000000000006000000000000000100000000000000070000000000000000000000000";
// char num_3[] = "00000000000000000000000000000000000000060000000000000001000000000000000600000000000000010000000000000007000000000000000000000000";
// char num4_[] = "00000000000000000000000000000000000000100000000000000010000000000000007000000000000000500000000000000050000000000000000000000000";
// char num_4[] = "00000000000000000000000000000000000000010000000000000001000000000000000700000000000000050000000000000005000000000000000000000000";
// char num5_[] = "00000000000000000000000000000000000000600000000000000010000000000000006000000000000000400000000000000070000000000000000000000000";
// char num_5[] = "00000000000000000000000000000000000000060000000000000001000000000000000600000000000000040000000000000007000000000000000000000000";
// char num6_[] = "00000000000000000000000000000000000000700000000000000050000000000000007000000000000000400000000000000030000000000000000000000000";
// char num_6[] = "00000000000000000000000000000000000000070000000000000005000000000000000700000000000000040000000000000003000000000000000000000000";
// char num9_[] = "00000000000000000000000000000000000000600000000000000010000000000000007000000000000000500000000000000070000000000000000000000000";
// char num_9[] = "00000000000000000000000000000000000000060000000000000001000000000000000700000000000000050000000000000007000000000000000000000000";
// char num7_[] = "00000000000000000000000000000000000000400000000000000040000000000000002000000000000000100000000000000070000000000000000000000000";
// char num_7[] = "00000000000000000000000000000000000000040000000000000004000000000000000200000000000000010000000000000007000000000000000000000000";
// char num8_[] = "00000000000000000000000000000000000000700000000000000050000000000000002000000000000000500000000000000070000000000000000000000000";
// char num_8[] = "00000000000000000000000000000000000000070000000000000005000000000000000200000000000000050000000000000007000000000000000000000000";
// char num0_[] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
// char num_0[] = "00000000000000000000000000000000000000020000000000000005000000000000000500000000000000050000000000000002000000000000000000000000";


char num2_[] = "00000000000000000000000000000000700000000000007040000000000000402000000000000020100000000000001070000000000000700000000000000000";
char num_2[] = "00000000000000000000000000000000070000000000000704000000000000040200000000000002010000000000000107000000000000070000000000000000";
char num1_[] = "00000000000000000000000000000000700000000000007020000000000000202000000000000020600000000000006020000000000000200000000000000000";
char num_1[] = "00000000000000000000000000000000070000000000000702000000000000020200000000000002060000000000000602000000000000020000000000000000";
char minus[] = "00000000000000000000000000000000000000000000000000000000000000008000000000000080000000000000000000000000000000000000000000000000";
char num3_[] = "00000000000000000000000000000000600000000000006010000000000000106000000000000060100000000000001070000000000000700000000000000000";
char num_3[] = "00000000000000000000000000000000060000000000000601000000000000010600000000000006010000000000000107000000000000070000000000000000";
char num4_[] = "00000000000000000000000000000000100000000000001010000000000000107000000000000070500000000000005050000000000000500000000000000000";
char num_4[] = "00000000000000000000000000000000010000000000000101000000000000010700000000000007050000000000000505000000000000050000000000000000";
char num5_[] = "00000000000000000000000000000000600000000000006010000000000000106000000000000060400000000000004070000000000000700000000000000000";
char num_5[] = "00000000000000000000000000000000060000000000000601000000000000010600000000000006040000000000000407000000000000070000000000000000";
char num6_[] = "00000000000000000000000000000000700000000000007050000000000000507000000000000070400000000000004030000000000000300000000000000000";
char num_6[] = "00000000000000000000000000000000070000000000000705000000000000050700000000000007040000000000000403000000000000030000000000000000";
char num9_[] = "00000000000000000000000000000000600000000000006010000000000000107000000000000070500000000000005070000000000000700000000000000000";
char num_9[] = "00000000000000000000000000000000060000000000000601000000000000010700000000000007050000000000000507000000000000070000000000000000";
char num7_[] = "00000000000000000000000000000000400000000000004040000000000000402000000000000020100000000000001070000000000000700000000000000000";
char num_7[] = "00000000000000000000000000000000040000000000000404000000000000040200000000000002010000000000000107000000000000070000000000000000";
char num8_[] = "00000000000000000000000000000000700000000000007050000000000000502000000000000020500000000000005070000000000000700000000000000000";
char num_8[] = "00000000000000000000000000000000070000000000000705000000000000050200000000000002050000000000000507000000000000070000000000000000";
char num0_[] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
char num_0[] = "00000000000000000000000000000000020000000000000205000000000000050500000000000005050000000000000502000000000000020000000000000000";
char *numbers[]= {num0_, num1_, num2_, num3_, num4_, num5_, num6_, num7_, num8_, num9_, num_0, num_1, num_2, num_3, num_4, num_5, num_6, num_7, num_8,  num_9};


void display_weather(double degrees){
    // int offset = 64 * 5;
    // for(int i = 0; i < 512; i++){
    //     if ((i >= offset) && (i < offset + degrees))
    //         cube[i] = 1;
    //     else 
    //         cube[i] = 0;

    // }
    for(int i = 0; i < 512; i++){
        cube[i] = 0;
    }
    char result[128];
    for(int i = 0; i < 128; i++){
        result[i] = 0;
    }

    if (degrees < 0){
        for (int i = 0; i < 128; i++) {
            result[i] |= minus[i];   
        }
        degrees = - degrees;
    } 
    int left_num = degrees / 10;
    int right_num = (int)degrees % 10;

    for (int i = 0; i < 128; i++) {
            result[i] |= numbers[left_num][i];
            result[i] |= numbers[right_num + 10][i];
    }
    string_param_to_SPI_char(result, cube);
}



/*
 *  http_native_request() demonstrates use of low level APIs to connect to a server,
 *  make a http request and read response. Event handler is not used in this case.
 *  Note: This approach should only be used in case use of low level APIs is required.
 *  The easiest way is to use esp_http_perform()
 */
static void http_native_request(char *city_for_weaher)
{
    
    char uri[150] = {0};   // Buffer to store response of http request
    sprintf(uri, "http://api.openweathermap.org/data/2.5/find?q=%s,RU&type=like&APPID=d94516628156a32f95567bb857f57fd6", city_for_weaher);
    esp_http_client_config_t config = {
        .url = uri,
        //.url = "http://api.openweathermap.org/data/2.5/find?q=Moscow,RU&type=like&APPID=d94516628156a32f95567bb857f57fd6",
    };
    // .url = "http://"CONFIG_EXAMPLE_HTTP_ENDPOINT"/get",
    //.url = "http://api.openweathermap.org/data/2.5/find?q=Moscow,RU&type=like&APPID=d94516628156a32f95567bb857f57fd6",
    // .url = "http://209.38.44.97/data/2.5/find?q=Moscow,RU&type=like&APPID=d94516628156a32f95567bb857f57fd6",
    //.url = "http://api.open-meteo.com/v1/forecast?latitude=55.45&longitude=37.36&current=temperature_2m",
    


    esp_http_client_handle_t client = esp_http_client_init(&config);
    ESP_LOGI(TAG, "URI: %s", config.url);
    // GET Request
    esp_http_client_set_method(client, HTTP_METHOD_GET);
    
    
    char output_buffer[MAX_HTTP_OUTPUT_BUFFER] = {0};   // Buffer to store response of http request
    int content_length = 0;
    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
    } else {
        content_length = esp_http_client_fetch_headers(client);
        if (content_length < 0) {
            ESP_LOGE(TAG, "HTTP client fetch headers failed");
        } else {
            int data_read = esp_http_client_read_response(client, output_buffer, MAX_HTTP_OUTPUT_BUFFER);
            if (data_read >= 0) {
                ESP_LOGI(TAG, "ITS HEAR HTTP GET Status = %d, content_length = %lld",
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));

                char buffer[32];
                double temperature;
                get_str_value(output_buffer, "temp", buffer);
                temperature = atoll(buffer) - 273;  // -273 - to get celsius from Kelvin
                ESP_LOGI(TAG, "Temperature in %s is %lf", city_for_weaher, temperature);
                display_weather(temperature); // ОТОБРАЖЕНИЕ ПОГОДЫ
            } else {
                ESP_LOGE(TAG, "Failed to read response");
            }
        }
    }
    esp_http_client_close(client);
}





void weather_API_client_Task(void *args){
    esp_err_t ret1 = nvs_flash_init();
    if (ret1 == ESP_ERR_NVS_NO_FREE_PAGES || ret1 == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret1 = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret1);
     //ESP_ERROR_CHECK(esp_netif_init());
     //ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    //ESP_ERROR_CHECK(example_connect());


    ESP_LOGI(TAG, "Waiting forAP connection");
    vTaskDelay(5000);


    //vTaskDelete(NULL);
    while(1)
    {
        if (weather_requests_are_enabled) 
        {
            if (weather_update_countdown <= 0)
            {
                ESP_LOGI(TAG, "Request weather for %s", city_for_weaher);
                http_native_request(city_for_weaher);
                weather_update_countdown = 20000;
            }
            else
            {
                weather_update_countdown -= 100;
            }
        }
        vTaskDelay(100);
    }
}



unsigned char code_to_send[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
unsigned char code_to_read[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
spi_transaction_t t[4];

void display_layer(int layer, char picture[]) // слои с нуля
{
   
    // Clean buffer
    for (int i = 0; i < NUM_SHIFT_REGISTERS; i++) {
        code_to_send[i] = 0x00;
    }

    // Column data
    for (int i = 0; i < 4; i++){
       code_to_send[11] |= (picture[3 * 8 + i] << i);
       code_to_send[11] |= (picture[2 * 8 + i] << (i + 4));
       code_to_send[10] |= (picture[1 * 8 + i] << i);
       code_to_send[10] |= (picture[0 * 8 + i] << (i + 4));

       code_to_send[8] |= (picture[3 * 8 + 4 + i] << i);
       code_to_send[8] |= (picture[2 * 8 + 4 + i] << (i + 4));
       code_to_send[7] |= (picture[1 * 8 + 4 + i] << i);
       code_to_send[7] |= (picture[0 * 8 + 4 + i] << (i + 4));

       code_to_send[5] |= (picture[4 * 8 + 4 + 3 - i] << i);
       code_to_send[5] |= (picture[5 * 8 + 4 + 3 - i] << (i + 4));
       code_to_send[4] |= (picture[6 * 8 + 4 + 3 - i] << i);
       code_to_send[4] |= (picture[7 * 8 + 4 + 3 - i] << (i + 4));

       code_to_send[2] |= (picture[4 * 8 + 3 - i] << i);
       code_to_send[2] |= (picture[5 * 8 + 3 - i] << (i + 4));
       code_to_send[1] |= (picture[6 * 8 + 3 - i] << i);
       code_to_send[1] |= (picture[7 * 8 + 3 - i] << (i + 4));
    }

    code_to_send[0] = 0x01 << layer;
    code_to_send[3] = 0x01 << layer;
    code_to_send[6] = 0x01 << layer;
    code_to_send[9] = 0x01 << layer;

    for (int i = 0; i < 4; i++) {
        t[i].length = 24;
        t[i].tx_buffer=&code_to_send[i * 3];
        t[i].rx_buffer=NULL;
        ret=spi_device_queue_trans(handle, &t[i], portMAX_DELAY);
    }
    

    vTaskDelay(1);
    
    // printf("Current code: %x %x %x | %x %x %x | %x %x %x | %x %x %x\n",
    //     code_to_send[0],  code_to_send[1], code_to_send[2],
    //     code_to_send[3],  code_to_send[4], code_to_send[5],
    //     code_to_send[6],  code_to_send[7], code_to_send[8],
    //     code_to_send[9],  code_to_send[10], code_to_send[11]
    // );
}

void display_cube(char d8_immage[]){
    const int delay_ms = 1;
    display_layer(0, &d8_immage[0]);
    vTaskDelay(delay_ms);
    display_layer(1, &d8_immage[64]);
    vTaskDelay(delay_ms);
    display_layer(2, &d8_immage[128]);
    vTaskDelay(delay_ms);
    display_layer(3, &d8_immage[192]);
    vTaskDelay(delay_ms);
    display_layer(4, &d8_immage[256]);
    vTaskDelay(delay_ms);
    display_layer(5, &d8_immage[320]);
    vTaskDelay(delay_ms);
    display_layer(6, &d8_immage[384]);
    vTaskDelay(delay_ms);
    display_layer(7, &d8_immage[448]);
    vTaskDelay(delay_ms);
    // char zeroes[64] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    // 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    // 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    // display_layer(0, zeroes);



}


char picture[64] = {1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0};
void display_cube_by_leds(void)
{
    for(int k = 0; k < 8; k++){
        for(int i = 0; i < 64; i++){
            for(int j = 0; j < 64; j++){
                picture[j] = 0;
            }
            picture[i] = 1;
            //printf("Current PICTURE: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n", picture[0],  picture[1], picture[2], picture[3], picture[4], picture[5], picture[6], picture[7], picture[8], picture[9], picture[10], picture[11], picture[12], picture[13], picture[14], picture[15]);
            //printf("displaying");
            display_layer(k, picture);
            vTaskDelay(10);

        }
    }
}



int image[64] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};                    

char cube_test[512] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1};

void SPI_Task(void *arg)
{
    //Configuration for the SPI bus
    spi_bus_config_t buscfg={
        .mosi_io_num=GPIO_MOSI,
        .miso_io_num=GPIO_MISO,
        .sclk_io_num=GPIO_SCLK,
        .quadwp_io_num=-1,
        .quadhd_io_num=-1
    };

    //Configuration for the SPI device on the other side of the bus
    spi_device_interface_config_t devcfg={
        .command_bits=0,
        .address_bits=0,
        .dummy_bits=0,
        .clock_speed_hz=400000,
        .duty_cycle_pos=128,        //50% duty cycle
        .mode=0,
        .spics_io_num=GPIO_CS,
        .cs_ena_posttrans=3,        //Keep the CS low 3 cycles after transaction, to stop slave from missing the last bit when CS has less propagation delay than CLK
        .queue_size=4
    };

    //GPIO config for the handshake line.
    gpio_config_t io_conf={
        .intr_type=GPIO_INTR_POSEDGE,
        .mode=GPIO_MODE_INPUT,
        .pull_up_en=1,
        .pin_bit_mask=(1<<GPIO_HANDSHAKE)
    };

    int n=0;

    //Create the semaphore.
    //rdySem=xSemaphoreCreateBinary();

    //Set up handshake line interrupt.
    gpio_config(&io_conf);
    gpio_install_isr_service(0);
    gpio_set_intr_type(GPIO_HANDSHAKE, GPIO_INTR_POSEDGE);
    gpio_isr_handler_add(GPIO_HANDSHAKE, gpio_handshake_isr_handler, NULL);

    //Initialize the SPI bus and add the device we want to send stuff to.
    ret=spi_bus_initialize(SENDER_HOST, &buscfg, SPI_DMA_CH_AUTO);
    assert(ret==ESP_OK);
    ret=spi_bus_add_device(SENDER_HOST, &devcfg, &handle);
    assert(ret==ESP_OK);

    //Assume the slave is ready for the first transmission: if the slave started up before us, we will not detect
    //positive edge on the handshake line.
    //xSemaphoreGive(rdySem);
    sleep(1);

    while(1) {
   
    
        //display_cube_by_leds();
        //cube_rising_image_animation();
        //display_layer(0, image);
        //layers_image_animation();
        //display_cube(NV);
        //sleep(1);
        display_cube(cube);
        vTaskDelay(5);
        n++;
    }

    //Never reached.
    ret=spi_bus_remove_device(handle);
    assert(ret==ESP_OK);
}

static void initialise_mdns(void)
{
    const char *hostname = "mucubes";

    //initialize mDNS
    ESP_ERROR_CHECK( mdns_init() );
    //set mDNS hostname (required if you want to advertise services)
    ESP_ERROR_CHECK( mdns_hostname_set(hostname) );
    ESP_LOGI(TAG, "mdns hostname set to: [%s]", hostname);
    //set default mDNS instance name
    ESP_ERROR_CHECK( mdns_instance_name_set("EXAMPLE_MDNS_INSTANCE") );

    //structure with TXT records
    mdns_txt_item_t serviceTxtData[3] = {
        {"board", "esp32c3"},
        {"u", "user"},
        {"p", "password"}
    };

    //initialize service
    ESP_ERROR_CHECK( mdns_service_add("ESP32-WebServer", "_http", "_tcp", 90, serviceTxtData, 3) );
    ESP_ERROR_CHECK( mdns_service_subtype_add_for_host("ESP32-WebServer", "_http", "_tcp", NULL, "_server") );


#if CONFIG_MDNS_PUBLISH_DELEGATE_HOST
    char *delegated_hostname;
    if (-1 == asprintf(&delegated_hostname, "%s-delegated", hostname)) {
        abort();
    }

    mdns_ip_addr_t addr4, addr6;
    esp_netif_str_to_ip4("10.0.0.1", &addr4.addr.u_addr.ip4);
    addr4.addr.type = ESP_IPADDR_TYPE_V4;
    esp_netif_str_to_ip6("fd11:22::1", &addr6.addr.u_addr.ip6);
    addr6.addr.type = ESP_IPADDR_TYPE_V6;
    addr4.next = &addr6;
    addr6.next = NULL;
    ESP_ERROR_CHECK( mdns_delegate_hostname_add(delegated_hostname, &addr4) );
    ESP_ERROR_CHECK( mdns_service_add_for_host("test0", "_http", "_tcp", delegated_hostname, 1234, serviceTxtData, 3) );
    free(delegated_hostname);
#endif // CONFIG_MDNS_PUBLISH_DELEGATE_HOST

    //add another TXT item
    ESP_ERROR_CHECK( mdns_service_txt_item_set("_http", "_tcp", "path", "/foobar") );
    //change TXT item value
    ESP_ERROR_CHECK( mdns_service_txt_item_set_with_explicit_value_len("_http", "_tcp", "u", "admin", strlen("admin")) );
}



void app_main(void)
{
    xTaskCreate(web_server_Task        , "Web_server_Task"        , 4096, NULL, 10, &WebServerTaskHandle);
    xTaskCreate(weather_API_client_Task, "weather_API_client_Task", 8192, NULL, 10, &WeatherClientTaskHandle);
    xTaskCreatePinnedToCore(SPI_Task, "SPI_Task", 4096, NULL, 10, &SPITaskHandle, 1);

    initialise_mdns();
}
