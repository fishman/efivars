#include "mxml/config.h"
#include "mxml/mxml.h"
#ifndef WIN32
#  include <unistd.h>
#endif /* !WIN32 */
#include <fcntl.h>
#ifndef O_BINARY
#  define O_BINARY 0
#endif /* !O_BINARY */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>



/*
 * Globals...
 */

int		event_counts[6];


static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}


char* getmac() {
  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  s.ifr_addr.sa_family = AF_INET;
  /* strncpy(s.ifr_name, "enp0s3", IFNAMSIZ-1); */

  size_t inl = 6;
  size_t outl;
  char* hell2;
  strcpy(s.ifr_name, "wlp3s0");
  if (0 == ioctl(fd, SIOCGIFHWADDR, &s)){
    int i;
    for (i = 0; i < 6; ++i)
    {
      /* printf("%02x", s.ifr_hwaddr.sa_data[i]); */
      /* printf("%02x", s.ifr_addr.sa_data[i]); */
    }
    /* int i; */
     /* s.ifr_addr.sa_data[0-5]; */
    /* apr_base64_encode_binary(hell2, s.ifr_hwaddr.sa_data, 6); */
    hell2 = base64_encode((unsigned char*)s.ifr_hwaddr.sa_data, inl, &outl);
    printf("%s\n", hell2);
  }
  unsigned char hello[6];
  hello[0] = 0x84;
  hello[1] = 0x38;
  hello[2] = 0x35;
  hello[3] = 0x61;
  hello[4] = 0xc9;
  hello[5] = 0x8e;



  hell2 = base64_encode(hello, inl, &outl);
  /* printf("%s\n", hell2); */
  return hell2;
}

void writevar(unsigned char* bootxml);
/*
 * 'main()' - Main entry for test program.
 */

int					/* O - Exit status */
main(int  argc,				/* I - Number of command-line args */
     char *argv[])			/* I - Command-line args */
{
  int			i;		/* Looping var */
  FILE			*fp;		/* File to read */
  int			fd;		/* File descriptor */
  mxml_index_t		*ind;		/* XML index */
  char			buffer[16384];	/* Save string */
  wchar_t   pwcs[32768];
  memset(pwcs, 0, 32768);
  size_t len;


  static const char	*types[] =	/* Strings for node types */
			{
			  "MXML_ELEMENT",
			  "MXML_INTEGER",
			  "MXML_OPAQUE",
			  "MXML_REAL",
			  "MXML_TEXT"
			};


  mxml_node_t *xml;    /* <?xml ... ?> */
  mxml_node_t *data;   /* <data> */
  mxml_node_t *node;   /* <node> */
  mxml_node_t *dict;   /* <node> */
  mxml_node_t *dict2;   /* <node> */
  mxml_node_t *group;  /* <group> */

  data = mxmlNewElement(NULL, "array");

  dict = mxmlNewElement(data, "dict");
  node = mxmlNewElement(dict, "key");
  mxmlNewText(node, 0, "IOMatch");
  dict2 = mxmlNewElement(dict, "dict");
  node = mxmlNewElement(dict2, "key");
  mxmlNewText(node, 0, "BSD Name");
  node = mxmlNewElement(dict2, "string");
  mxmlNewText(node, 0, "en0");
  node = mxmlNewElement(dict2, "key");
  mxmlNewText(node, 0, "IOProviderClass");
  node = mxmlNewElement(dict2, "string");
  mxmlNewText(node, 0, "IONetworkInterface");
  node = mxmlNewElement(dict, "key");
  mxmlNewText(node, 0, "BLMACAddress");
  node = mxmlNewElement(dict, "data");
  mxmlNewText(node, 0, getmac());
  /* dict2 = mxmlNewElement(dict, "dict"); */
  /* node = mxmlNewElement(dict2, "key"); */
  /* mxmlNewText(node, 0, "IOEFIDevicePathType"); */
  /* node = mxmlNewElement(dict2, "string"); */
  /* mxmlNewText(node, 0, "MessagingIPv4"); */
  /* node = mxmlNewElement(dict2, "key"); */
  /* mxmlNewText(node, 0, "RemoteIpAddress"); */
  /* node = mxmlNewElement(dict2, "string"); */
  /* mxmlNewText(node, 0, "192.168.5.1"); */


  mxmlSaveString(data, buffer, sizeof(buffer), MXML_NO_CALLBACK);
  writevar((unsigned char*) buffer);
  fp = fopen("filename.xml", "w");
  fwrite(buffer, strlen(buffer), 1, fp);
  /* len = mbstowcs( pwcs, buffer, 32768); */
  /* fwrite(pwcs, len, 1, fp); */
  fclose(fp);
}
