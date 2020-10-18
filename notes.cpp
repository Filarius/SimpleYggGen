//
// Created by BIZONER on 01.10.2020.
//

static std::string readStringFromFile(
        const std::string& filename )
{
    std::ifstream is(filename, std::ios::binary);
    if (!is.good()) {
        return nullptr;
    }

    size_t filesize = 0;
    is.seekg(0, std::ios::end);
    filesize = (size_t)is.tellg();
    is.seekg(0, std::ios::beg);

    std::string source{
            std::istreambuf_iterator<char>(is),
            std::istreambuf_iterator<char>() };

    return source;
}

char result[65];

sha256_init(2048);
crypt_and_print((char*)"1");
crypt_and_print((char*)"12");
crypt_and_print((char*)"123");
crypt_and_print((char*)"1234567890123456789012345678901234567890123456789012345678901234567890");
return 0;




try
{
// Discover number of platforms
std::vector<cl::Platform> platforms;
cl::Platform::get(&platforms);
std::cout << "\nNumber of OpenCL plaforms: " << platforms.size() << std::endl;

// Investigate each platform
std::cout << "\n-------------------------" << std::endl;
for (std::vector<cl::Platform>::iterator plat = platforms.begin(); plat != platforms.end(); plat++)
{
std::string s;
plat->getInfo(CL_PLATFORM_NAME, &s);
std::cout << "Platform: " << s << std::endl;

plat->getInfo(CL_PLATFORM_VENDOR, &s);
std::cout << "\tVendor:  " << s << std::endl;

plat->getInfo(CL_PLATFORM_VERSION, &s);
std::cout << "\tVersion: " << s << std::endl;

// Discover number of devices
std::vector<cl::Device> devices;
plat->getDevices(CL_DEVICE_TYPE_ALL, &devices);
std::cout << "\n\tNumber of devices: " << devices.size() << std::endl;

// Investigate each device
for (std::vector<cl::Device>::iterator dev = devices.begin(); dev != devices.end(); dev++ )
{
    std::cout << "\t-------------------------" << std::endl;

    dev->getInfo(CL_DEVICE_NAME, &s);
    std::cout << "\t\tName: " << s << std::endl;

    dev->getInfo(CL_DEVICE_OPENCL_C_VERSION, &s);
    std::cout << "\t\tVersion: " << s << std::endl;

    int i;
    dev->getInfo(CL_DEVICE_MAX_COMPUTE_UNITS, &i);
    std::cout << "\t\tMax. Compute Units: " << i << std::endl;

    size_t size;
    dev->getInfo(CL_DEVICE_LOCAL_MEM_SIZE, &size);
    std::cout << "\t\tLocal Memory Size: " << size/1024 << " KB" << std::endl;

    dev->getInfo(CL_DEVICE_GLOBAL_MEM_SIZE, &size);
    std::cout << "\t\tGlobal Memory Size: " << size/(1024*1024) << " MB" << std::endl;

    dev->getInfo(CL_DEVICE_MAX_MEM_ALLOC_SIZE, &size);
    std::cout << "\t\tMax Alloc Size: " << size/(1024*1024) << " MB" << std::endl;

    dev->getInfo(CL_DEVICE_MAX_WORK_GROUP_SIZE, &size);
    std::cout << "\t\tMax Work-group Total Size: " << size << std::endl;

    std::vector<size_t> d;
    dev->getInfo(CL_DEVICE_MAX_WORK_ITEM_SIZES, &d);
    std::cout << "\t\tMax Work-group Dims: (";
    for (std::vector<size_t>::iterator st = d.begin(); st != d.end(); st++)
        std::cout << *st << " ";
    std::cout << "\x08)" << std::endl;

    std::cout << "\t-------------------------" << std::endl;

}

std::cout << "\n-------------------------\n";
}

}
catch(long e)
{

}

return 0;



























// Check available opencl platforms
std::vector<cl::Platform> all_platforms;
cl::Platform::get(&all_platforms);
if(all_platforms.size()==0){
std::cout<<" No platforms found. Check OpenCL installation!\n";
exit(1);
}
for(int i=0;i<all_platforms.size();i++){
std::cout << "Platform available:  "<<all_platforms[i].getInfo<CL_PLATFORM_NAME>()<<"\n";
}
cl::Platform default_platform=all_platforms[1];
std::cout << "Using platform: "<<default_platform.getInfo<CL_PLATFORM_NAME>()<<"\n";

//Check available opencl devices
std::vector<cl::Device> all_devices;
default_platform.getDevices(CL_DEVICE_TYPE_ALL, &all_devices);
if(all_devices.size()==0){
std::cout<<" No devices found. Check OpenCL installation!\n";
exit(1);
}
for(int i=0;i<all_devices.size();i++){
std::cout<< "Device available: "<<all_devices[i].getInfo<CL_DEVICE_NAME>()<<"\n";
}
cl::Device default_device=all_devices[0];
std::cout<< "Using device: "<<default_device.getInfo<CL_DEVICE_NAME>()<<"\n";

cl::Context context(default_device);
cl::CommandQueue queue(context);

cl::Program::Sources sources;
std::ifstream file("sha512.cl");
std::stringstream buffer;
buffer << file.rdbuf();
auto src = buffer.str();
cl_int err;
cl::Program prog = cl::Program(context,src,false,&err);
prog.build(NULL,NULL);

int q[64*1000];
cl::Buffer cb1= cl::Buffer(context,CL_MEM_READ_ONLY|CL_MEM_COPY_HOST_PTR,sizeof(byte)*32*1000,q,NULL);
cl::Buffer cb2 = cl::Buffer(context,CL_MEM_READ_WRITE,sizeof(byte)*64*1000,NULL,NULL);

return 0;




//  fd = fopen("sha512.cl",OFN_RDONLY);




#include "sha256cl.h"


void crypt_and_print(char* input)
{
    char result[65];
    sha256_crypt(input,result);
    printf("'%s':\n%s\n", input, result);
}




