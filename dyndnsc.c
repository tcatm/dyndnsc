#include <curl/curl.h>
#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define NIPQUAD(addr) \
  ((unsigned char *)&addr)[0], \
  ((unsigned char *)&addr)[1], \
  ((unsigned char *)&addr)[2], \
  ((unsigned char *)&addr)[3]

#define NIPQUAD_FMT "%u.%u.%u.%u"

#define NIP6(addr) \
  ntohs((addr).s6_addr16[0]), \
  ntohs((addr).s6_addr16[1]), \
  ntohs((addr).s6_addr16[2]), \
  ntohs((addr).s6_addr16[3]), \
  ntohs((addr).s6_addr16[4]), \
  ntohs((addr).s6_addr16[5]), \
  ntohs((addr).s6_addr16[6]), \
  ntohs((addr).s6_addr16[7])

#define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"

struct address {
  unsigned int ifa_flags;
  struct timespec ifa_prefered;
  struct in6_addr ip;
};

struct list {
  struct address *addrs;
  size_t size;
};

struct list list = {};
struct in6_addr best_ip = {};
bool sent = false;

char *url, *keyfile, *certfile;

void dump() {
  printf("\nAddresses:\n");
  for (int i = 0; i < list.size; i++) {
    struct address *addr = &list.addrs[i];
    printf("  " NIP6_FMT " ", NIP6(addr->ip));
    printf("%usec\n", addr->ifa_prefered.tv_sec);
  }
}

void remove_entry(struct address *addr) {
  if (list.size == 0)
    return;

  for (int i = 0; i < list.size; i++)
    if (memcmp(&addr->ip, &list.addrs[i].ip, sizeof(struct in6_addr)) == 0) {
      memmove(&list.addrs[i], &list.addrs[i+1], sizeof(struct address) * (list.size - i));
      list.addrs = realloc(list.addrs, sizeof(struct address) * (list.size - 1));
      list.size--;
      break;
    }
}

void add_entry(struct address *addr) {
  list.size++;
  list.addrs = realloc(list.addrs, sizeof(struct address) * list.size);
  list.addrs[list.size - 1] = *addr;
}

void send_request() {
  printf("new best!\n");

  char postdata[INET6_ADDRSTRLEN];
  sprintf(postdata, NIP6_FMT, NIP6(best_ip));

  CURL *curl = curl_easy_init();
  CURLcode res;

  do {
    if (curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L) != CURLE_OK) {
      fprintf(stderr, "Error!\n");
      break;
    }

    curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
    curl_easy_setopt(curl, CURLOPT_SSLCERT, certfile);
    curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
    curl_easy_setopt(curl, CURLOPT_SSLKEY, keyfile);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);

    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

    sent = true;
    printf("Update successful.\n");
  } while(false);

  curl_easy_cleanup(curl);
}

int cmp_addr(const void *a, const void *b) {
  const struct address *da = (const struct address *)a;
  const struct address *db = (const struct address *)b;

  return (da->ifa_prefered.tv_sec < db->ifa_prefered.tv_sec) -
         (da->ifa_prefered.tv_sec > db->ifa_prefered.tv_sec);
}

void find_best() {
  qsort(list.addrs, list.size, sizeof(struct address), cmp_addr);
  dump();

  if (list.size == 0)
    return;

  if (memcmp(&list.addrs[0].ip, &best_ip, sizeof(struct in6_addr)) != 0) {
    // TODO allow static suffix
    best_ip = list.addrs[0].ip;
    sent = false;
    send_request();
  }
}

void del_addr(struct address *addr) {
  remove_entry(addr);
  find_best();
}

void add_addr(struct address *addr) {
  remove_entry(addr);
  add_entry(addr);
  find_best();
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);

  url = NULL;
  keyfile = NULL;
  certfile = NULL;

  int opt;
  while ((opt = getopt(argc, argv, "p:c:u:s:")) != -1) {
    switch (opt) {
      case 'p':
        keyfile = strdup(optarg);
        break;
      case 'c':
        certfile = strdup(optarg);
        break;
      case 'u':
        url = strdup(optarg);
        break;
      case 's':
        fprintf(stderr, "ERROR: -s not yet implemented!\n");
        exit(1);
        break;
      default:
        fprintf(stderr, "ERROR: unknown option \"-%c\"!\n", opt);
        exit(1);
    }
  }

  if (url == NULL) {
    fprintf(stderr, "ERROR: No URL (-u) given!\n");
    exit(1);
  }

  if (access(keyfile, R_OK) == -1) {
    fprintf(stderr, "ERROR: Can not open private key for reading: %s\n", strerror(errno));
    exit(1);
  }

  if (access(certfile, R_OK) == -1) {
    fprintf(stderr, "ERROR: Can not open certificate for reading: %s\n", strerror(errno));
    exit(1);
  }

  // parse options
  // -p
  // -c
  // -u
  // [-s]


  curl_global_init(CURL_GLOBAL_DEFAULT);

  struct {
    struct nlmsghdr n;
    struct ifaddrmsg r;
  } req;

  struct rtattr *rta;
  struct sockaddr_in6 *sin6p;
  struct sockaddr_in *sinp;
  int status;
  char buf[16384];
  struct nlmsghdr *nlmp;
  struct ifaddrmsg *rtmp;
  struct rtattr *rtatp;
  int rtattrlen;
  struct in_addr *inp;
  struct in6_addr *in6p;
  struct ifa_cacheinfo *cache_info;

  int fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

  struct sockaddr_nl addr;

  memset (&addr,0,sizeof(addr));
  addr.nl_family = AF_NETLINK;
  addr.nl_groups = RTMGRP_IPV6_IFADDR;

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    perror ("bind failure\n");
    return 1;
  }

  memset(&req, 0, sizeof(req));
  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
  req.n.nlmsg_type = RTM_GETADDR;
  req.r.ifa_family = AF_INET6;

  rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
  rta->rta_len = RTA_LENGTH(16);

  status = send(fd, &req, req.n.nlmsg_len, 0);

  if (status < 0) {
    perror("send");
    return 1;
  }

  struct timeval tv = {
    .tv_sec = 60
  };

  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

  while (1) {
    status = recv(fd, buf, sizeof(buf), 0);

    if (status < 0) {
      if (errno == EAGAIN) {
        if (!sent)
          send_request();

        continue;
      }
      perror("recv");
      return 1;
    }

    if(status == 0){
      printf("EOF\n");
      return 1;
    }

    /* Typically the message is stored in buf, so we need to parse the message to *
     * get the required data for our display. */

    for(nlmp = (struct nlmsghdr *)buf; status > sizeof(*nlmp);){
      int len = nlmp->nlmsg_len;
      int req_len = len - sizeof(*nlmp);

      if (req_len<0 || len>status) {
        printf("error\n");
        return -1;
      }

      if (!NLMSG_OK(nlmp, status)) {
        printf("NLMSG not OK\n");
        return 1;
      }

      rtmp = (struct ifaddrmsg *)NLMSG_DATA(nlmp);
      rtatp = (struct rtattr *)IFA_RTA(rtmp);

      struct address addr = {};

      addr.ifa_flags = rtmp->ifa_flags;

      rtattrlen = IFA_PAYLOAD(nlmp);

      clock_gettime(CLOCK_MONOTONIC, &addr.ifa_prefered);

      for (; RTA_OK(rtatp, rtattrlen); rtatp = RTA_NEXT(rtatp, rtattrlen)) {
        if(rtatp->rta_type == IFA_CACHEINFO){
          cache_info = (struct ifa_cacheinfo *)RTA_DATA(rtatp);
          addr.ifa_prefered.tv_sec += cache_info->ifa_prefered == 0xFFFFFFFFU ? 100 * 86400 : cache_info->ifa_prefered;
        }

        if(rtatp->rta_type == IFA_ADDRESS){
          in6p = (struct in6_addr *)RTA_DATA(rtatp);
          addr.ip = *in6p;

        }
      }

      if ((ntohs((addr.ip).s6_addr16[0]) & 0xE000) == 0x2000) {
        if (nlmp->nlmsg_type == RTM_DELADDR) {
          del_addr(&addr);
        } else if (nlmp->nlmsg_type == RTM_NEWADDR) {
          if (addr.ifa_flags & (IFA_F_TEMPORARY | IFA_F_TENTATIVE | IFA_F_DADFAILED)) {
            del_addr(&addr);
          } else {
            add_addr(&addr);
          }
        }
      }

      status -= NLMSG_ALIGN(len);
      nlmp = (struct nlmsghdr*)((char*)nlmp + NLMSG_ALIGN(len));
    }
  }
}

