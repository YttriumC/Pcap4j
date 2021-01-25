#define HAVE_REMOTE

#include "cf_vbnm_pcap4j_AbstractWinPcap.h"
#include "pcap.h"

#ifndef _PCAP4J_C
#define _PCAP4J_C
#define PCAP_RELEASE 
#define jenv (*env)
#define log(msg) fprintf(stderr, msg)
#define log2(style, info) fprintf(stderr, style, info)
// #ifdef __cplusplus
// extern "C"
// {
// #endif
/*
 * 全局变量
 */
pcap_t *adhandle;
pcap_if_t *alldevs;
jsize alldevs_num;
//PCAP_ERRBUF_SIZE 256
char errbuf[PCAP_ERRBUF_SIZE];

/*
 * Class:     cf_vbnm_pcap4j_AbstractWinPcap
 * Method:    findDevices0
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_cf_vbnm_pcap4j_AbstractWinPcap_findDevices0(
    JNIEnv *env, jobject jobj)
{
    //log("findDev\n");
    jint length;
    //-1 is returned on failure, in which case errbuf is filled in with an
    //appropriate error message; 0 is returned on success.
    //例如，该进程可能没有足够的特权来打开它们进行捕获；
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        length = 0;
    }
    else
    {
        pcap_if_t *d;
        for (length = 0, d = alldevs; d; d = d->next)
        {
            ++length;
        }
    }
    alldevs_num = length;
    //log("findDev_exit\n");
    return length;
}

/*
 * Class:     cf_vbnm_pcap4j_AbstractWinPcap
 * Method:    obtainDevicesList
 * Signature: ()[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL
Java_cf_vbnm_pcap4j_AbstractWinPcap_obtainDevicesList(
    JNIEnv *env, jobject jobj)
{
    //log("obtainDevList\n");
    pcap_if_t *d;
    char buf[512];
    jsize i = 0;
    jstring jdev_scription;
    jclass string_class = (*env)->FindClass(env, "java/lang/String");
    jobjectArray string_array = (*env)->NewObjectArray( //
        env, alldevs_num, string_class, NULL);
    for (d = alldevs; d; d = d->next, i++)
    {
        if (d->description)
            sprintf(buf, "%s (%s)", d->name, d->description);
        else
            sprintf(buf, "%s (No description available)", d->name);
        jdev_scription = jenv->NewStringUTF(env, buf);
        jenv->SetObjectArrayElement(env, string_array, i, jdev_scription);
        //log("obtainDevList_ex\n");
    }
    //log("obtainDevList_ex\n");
    return string_array;
}

/*
 * Class:     cf_vbnm_pcap4j_AbstractWinPcap
 * Method:    openDevice0
 * Signature: (IIZ)V
 */
JNIEXPORT void JNICALL Java_cf_vbnm_pcap4j_AbstractWinPcap_openDevice0(
    JNIEnv *env, jobject jobj, jint index, jint maxCapLen, jint flags, jint timeout)
{
    //log("openDev\n");
    pcap_if_t *d;
    jint i = 0;
    for (d = alldevs; i < index; d = d->next, i++)
        ;
    if ((adhandle = pcap_open(d->name,   // 设备名
                              maxCapLen, // 要捕捉的数据包的部分
                              flags,     // 混杂模式
                              timeout,   // 读取超时时间
                              NULL,      // 远程机器验证
                              errbuf)) == NULL)
    {
        //log2("\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        char buf[512];
        jclass open_ex_class = jenv->FindClass(
            env, "cf/vbnm/pcap4j/exceptions/OpenDeviceException");
        jmethodID open_ex_constructor = jenv->GetMethodID(
            env, open_ex_class, "<init>", "(Ljava/lang/String;)V");
        sprintf(buf, "打开设备失败:%s", d->name);
        jstring err_msg = jenv->NewStringUTF(env, buf);
        jobject open_ex_obj = jenv->NewObject(
            env, open_ex_class, open_ex_constructor, err_msg);
        jenv->Throw(env, open_ex_obj);
    }
    pcap_freealldevs(alldevs);
    //log("openDev_ex\n");
}

JNIEnv *loop_cap_call_env;
jobject loop_cap_call_obj;
jclass loop_cap_call_class;
jmethodID loop_cap_call_method;

void pcap_loop_callback(
    u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
    //log("loop_callback\n");
    jbyteArray pkt_jbarr = (*loop_cap_call_env)->NewByteArray( //
        loop_cap_call_env, pkt_header->caplen);
    //log("jarr");
    (*loop_cap_call_env)->SetByteArrayRegion( //
        loop_cap_call_env, pkt_jbarr, 0, pkt_header->caplen, pkt_data);
    //log("set bytearr");
    (*loop_cap_call_env)->CallVoidMethod(     //
        loop_cap_call_env, loop_cap_call_obj, //
        loop_cap_call_method, pkt_jbarr,      //
        pkt_header->len, pkt_header->ts.tv_sec, pkt_header->ts.tv_usec);
    //log("call callback");
}

/*
 * Class:     cf_vbnm_pcap4j_AbstractWinPcap
 * Method:    loopCapture0
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_cf_vbnm_pcap4j_AbstractWinPcap_loopCapture0(
    JNIEnv *env, jobject jobj, jint cnt)
{
    //log("loopCap\n");
    loop_cap_call_env = env;
    loop_cap_call_obj = jobj;
    loop_cap_call_class = jenv->GetObjectClass(env, jobj);
    loop_cap_call_method = jenv->GetMethodID(
        env, loop_cap_call_class, "captureLoopCallback", "([BIII)V");
    //pcap_t * p,int cnt,pcap_handler callback,u_char * user
    //log("startloop\n");
    pcap_loop(adhandle, cnt, pcap_loop_callback, NULL);
    //log("loopCap_ex\n");
}

/*
 * Class:     cf_vbnm_pcap4j_AbstractWinPcap
 * Method:    breakLoop0
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_cf_vbnm_pcap4j_AbstractWinPcap_breakLoop0(
    JNIEnv *env, jobject jobj)
{
    //log("breakloop\n");
    pcap_breakloop(adhandle);
    //log("breakloop_ex\n");
}

/*
 * Class:     cf_vbnm_pcap4j_AbstractWinPcap
 * Method:    capNext0
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_cf_vbnm_pcap4j_AbstractWinPcap_capNext0(
    JNIEnv *env, jobject jobj)
{
    //log("capNext\n");
    struct pcap_pkthdr pkthdr;
    const u_char *pkt = pcap_next(adhandle, &pkthdr);
    if (pkt == NULL)
        return jenv->NewByteArray(env, 0);
    jbyteArray pkt_jarr = jenv->NewByteArray(env, pkthdr.caplen);
    jenv->SetByteArrayRegion(env, pkt_jarr, 0, pkthdr.caplen, pkt);
    //log("capNext_ex\n");
    return pkt_jarr;
}

/*
 * Class:     cf_vbnm_pcap4j_AbstractWinPcap
 * Method:    sendPacket0
 * Signature: ([BI)Z
 */
JNIEXPORT jboolean JNICALL Java_cf_vbnm_pcap4j_AbstractWinPcap_sendPacket0(
    JNIEnv *env, jobject jobj, jbyteArray pkt, jint send_len)
{
    //log("sendPkt\n");
    u_char *pkt_data = jenv->GetByteArrayElements(env, pkt, JNI_FALSE);
    //log("sendPkt_ex\n");
    return (jboolean)!pcap_sendpacket(adhandle, pkt_data, jenv->GetArrayLength(env, pkt));
}

/*
 * Class:     cf_vbnm_pcap4j_AbstractWinPcap
 * Method:    close0
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_cf_vbnm_pcap4j_AbstractWinPcap_close0(
    JNIEnv *env, jobject jobj)
{
    //log("close\n");
    pcap_close(adhandle);
    //log("cloae_ex\n");
}

// #ifdef __cplusplus
// }
// #endif
#endif