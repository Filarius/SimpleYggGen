#include "sha256cl.h"

#define MULTI_LINE_STRING(a) #a
static const char *KernelSource = MULTI_LINE_STRING(
#ifndef uint32_t
#define uint32_t unsigned int
#endif

#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19


        uint rotr(uint x, int n) {
        if (n < 32) return (x >> n) | (x << (32 - n));
        return x;
}

        uint ch(uint x, uint y, uint z) {
        return (x & y) ^ (~x & z);
}

        uint maj(uint x, uint y, uint z) {
        return (x & y) ^ (x & z) ^ (y & z);
}

        uint sigma0(uint x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

        uint sigma1(uint x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

        uint gamma0(uint x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

        uint gamma1(uint x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}


        __kernel void sha256_crypt_kernel(__global uint *data_info,__global char *plain_key,  __global uint *digest){
        int t, gid, msg_pad;
        int stop, mmod;
        uint i, ulen, item, total;
        uint W[80], temp, A,B,C,D,E,F,G,H,T1,T2;
        uint num_keys = data_info[1];
        int current_pad;

        uint K[64]={
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        msg_pad=0;

        ulen = data_info[2];
        total = ulen%64>=56?2:1 + ulen/64;

//  printf("ulen: %u total:%u\n", ulen, total);

        digest[0] = H0;
        digest[1] = H1;
        digest[2] = H2;
        digest[3] = H3;
        digest[4] = H4;
        digest[5] = H5;
        digest[6] = H6;
        digest[7] = H7;
        for(item=0; item<total; item++)
        {

            A = digest[0];
            B = digest[1];
            C = digest[2];
            D = digest[3];
            E = digest[4];
            F = digest[5];
            G = digest[6];
            H = digest[7];

#pragma unroll
            for (t = 0; t < 80; t++){
                W[t] = 0x00000000;
            }
            msg_pad=item*64;
            if(ulen > msg_pad)
            {
                current_pad = (ulen-msg_pad)>64?64:(ulen-msg_pad);
            }
            else
            {
                current_pad =-1;
            }

//  printf("current_pad: %d\n",current_pad);
            if(current_pad>0)
            {
                i=current_pad;

                stop =  i/4;
//    printf("i:%d, stop: %d msg_pad:%d\n",i,stop, msg_pad);
                for (t = 0 ; t < stop ; t++){
                    W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
                    W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 1]) << 16;
                    W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 2]) << 8;
                    W[t] |= (uchar)  plain_key[msg_pad + t * 4 + 3];
//printf("W[%u]: %u\n",t,W[t]);
                }
                mmod = i % 4;
                if ( mmod == 3){
                    W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
                    W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 1]) << 16;
                    W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 2]) << 8;
                    W[t] |=  ((uchar) 0x80) ;
                } else if (mmod == 2) {
                    W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
                    W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 1]) << 16;
                    W[t] |=  0x8000 ;
                } else if (mmod == 1) {
                    W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
                    W[t] |=  0x800000 ;
                } else /*if (mmod == 0)*/ {
                    W[t] =  0x80000000 ;
                }

                if (current_pad<56)
                {
                    W[15] =  ulen*8 ;
//printf("ulen avlue 2 :w[15] :%u\n", W[15]);
                }
            }
            else if(current_pad <0)
            {
                if( ulen%64==0)
                    W[0]=0x80000000;
                W[15]=ulen*8;
//printf("ulen avlue 3 :w[15] :%u\n", W[15]);
            }

            for (t = 0; t < 64; t++) {
                if (t >= 16)
                    W[t] = gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16];
                T1 = H + sigma1(E) + ch(E, F, G) + K[t] + W[t];
                T2 = sigma0(A) + maj(A, B, C);
                H = G; G = F; F = E; E = D + T1; D = C; C = B; B = A; A = T1 + T2;
            }
            digest[0] += A;
            digest[1] += B;
            digest[2] += C;
            digest[3] += D;
            digest[4] += E;
            digest[5] += F;
            digest[6] += G;
            digest[7] += H;

//  for (t = 0; t < 80; t++)
//    {
//    printf("W[%d]: %u\n",t,W[t]);
//    }
        }


}

);






static cl_platform_id platform_id = NULL;
static cl_device_id device_id = NULL;
static cl_uint ret_num_devices;
static cl_uint ret_num_platforms;
static cl_context context;

static cl_int ret;

static char* source_str;
static size_t source_size;

static cl_program program;
static cl_kernel kernel;
static cl_command_queue command_queue;


static cl_mem pinned_saved_keys, pinned_partial_hashes, buffer_out, buffer_keys, data_info;
static cl_uint *partial_hashes;
static cl_uint *res_hashes;
static char *saved_plain;
static unsigned int datai[3];
static int have_full_hashes;

static size_t kpc = 4;

static size_t global_work_size=1;
static size_t local_work_size=1;
static size_t string_len;

void load_source();
void createDevice();
void createkernel();
void create_clobj();

void crypt_all();


void sha256_init(size_t user_kpc)
{
    kpc = user_kpc;
    load_source();
    createDevice();
    createkernel();
    create_clobj();
}

void sha256_crypt(char* input, char* output)
{
    int i;
    string_len = strlen(input);
    global_work_size = 1;
    datai[0] = SHA256_PLAINTEXT_LENGTH;
    datai[1] = global_work_size;
    datai[2] = string_len;
    memcpy(saved_plain, input, string_len+1);

    crypt_all();

    for(i=0; i<SHA256_RESULT_SIZE; i++)
    {
        sprintf(output+i*8,"%08x", partial_hashes[i]);

    }
}

void crypt_all()
{
    //printf("%s\n",saved_plain);
    ret = clEnqueueWriteBuffer(command_queue, data_info, CL_TRUE, 0, sizeof(unsigned int) * 3, datai, 0, NULL, NULL);
    ret = clEnqueueWriteBuffer(command_queue, buffer_keys, CL_TRUE, 0, SHA256_PLAINTEXT_LENGTH * kpc, saved_plain, 0, NULL, NULL);
    // printf("%s\n",buffer_keys);
    ret = clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL);

    ret = clFinish(command_queue);
    // read back partial hashes
    ret = clEnqueueReadBuffer(command_queue, buffer_out, CL_TRUE, 0, sizeof(cl_uint) * SHA256_RESULT_SIZE, partial_hashes, 0, NULL, NULL);
    have_full_hashes = 0;
}

void load_source()
{
    FILE *fp;

    fp = fopen("sha256.cl", "r");
    if (!fp) {
        fprintf(stderr, "Failed to load kernel.\n");
        exit(1);
    }
    source_str = (char*)malloc(MAX_SOURCE_SIZE);
    source_size = fread( source_str, 1, MAX_SOURCE_SIZE, fp);
    fclose( fp );
}

void create_clobj(){
    pinned_saved_keys = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, (SHA256_PLAINTEXT_LENGTH)*kpc, NULL, &ret);
    saved_plain = (char*)clEnqueueMapBuffer(command_queue, pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0, (SHA256_PLAINTEXT_LENGTH)*kpc, 0, NULL, NULL, &ret);
    memset(saved_plain, 0, SHA256_PLAINTEXT_LENGTH * kpc);
    res_hashes = (cl_uint *)malloc(sizeof(cl_uint) * SHA256_RESULT_SIZE);
    memset(res_hashes, 0, sizeof(cl_uint) * SHA256_RESULT_SIZE);
    pinned_partial_hashes = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * SHA256_RESULT_SIZE, NULL, &ret);
    partial_hashes = (cl_uint *) clEnqueueMapBuffer(command_queue, pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, sizeof(cl_uint) * SHA256_RESULT_SIZE, 0, NULL, NULL, &ret);
    memset(partial_hashes, 0, sizeof(cl_uint) * SHA256_RESULT_SIZE);

    buffer_keys = clCreateBuffer(context, CL_MEM_READ_ONLY, (SHA256_PLAINTEXT_LENGTH) * kpc, NULL, &ret);
    buffer_out = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(cl_uint) * SHA256_RESULT_SIZE, NULL, &ret);
    data_info = clCreateBuffer(context, CL_MEM_READ_ONLY, sizeof(unsigned int) * 3, NULL, &ret);

    clSetKernelArg(kernel, 0, sizeof(data_info), (void *) &data_info);
    clSetKernelArg(kernel, 1, sizeof(buffer_keys), (void *) &buffer_keys);
    clSetKernelArg(kernel, 2, sizeof(buffer_out), (void *) &buffer_out);
}

void createDevice()
{
    ret = clGetPlatformIDs(1, &platform_id, &ret_num_platforms);
    ret = clGetDeviceIDs( platform_id, CL_DEVICE_TYPE_ALL, 1, &device_id, &ret_num_devices);

    context = clCreateContext( NULL, 1, &device_id, NULL, NULL, &ret);
}

void createkernel()
{
    program = clCreateProgramWithSource(context, 1, (const char **)&source_str, (const size_t *)&source_size, &ret);
    ret = clBuildProgram(program, 1, &device_id, NULL, NULL, NULL);
    kernel = clCreateKernel(program, "sha256_crypt_kernel", &ret);
    command_queue = clCreateCommandQueue(context, device_id, 0, &ret);
}
