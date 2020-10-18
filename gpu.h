
#define CL_HPP_TARGET_OPENCL_VERSION 110
#define CL_TARGET_OPENCL_VERSION 110
#define CL_HPP_MINIMUM_OPENCL_VERSION 110
#define CL_HPP_ENABLE_EXCEPTIONS
#include <iostream>
#include <fstream>
#include <CL/cl2.hpp>


std::string gpuGetStringFromFile(std::string fileName){
    std::ifstream file(fileName);
    std::string sourceCode(std::istreambuf_iterator<char>(file),(std::istreambuf_iterator<char>()));
    return sourceCode;
}

void gpuPrintInfo(){
    std::vector<cl::Platform> platforms;
    cl::Platform::get(&platforms);
    int i = 0;
    //list available platforms
    for(cl::Platform platform : platforms){
        std::string s;
        std::cout << "Platform id: " << i++ << std::endl;
        platform.getInfo(CL_PLATFORM_NAME, &s);
        std::cout << "Platform: " << s << std::endl;
        platform.getInfo(CL_PLATFORM_VENDOR, &s);
        std::cout << "\tVendor:  " << s << std::endl;
        platform.getInfo(CL_PLATFORM_VERSION, &s);
        std::cout << "\tVersion: " << s << std::endl;
        platform.getInfo(CL_PLATFORM_PROFILE, &s);
        std::cout << "\tProfile: " << s << std::endl;
        platform.getInfo(CL_PLATFORM_EXTENSIONS, &s);
        std::cout << "\tPlatform Exts: " << s << std::endl;

        // list available devices
        std::vector<cl::Device> devices;
        platform.getDevices(CL_DEVICE_TYPE_ALL, &devices);
        std::cout << "\n\tNumber of devices: " << devices.size() << std::endl;
        int j=0;
        for(cl::Device device : devices){
            std::cout << "\t\tDevice ID: " << j++ << std::endl;
            device.getInfo(CL_DEVICE_NAME, &s);
            std::cout << "\t\tName: " << s << std::endl;
            device.getInfo(CL_DEVICE_VENDOR, &s);
            std::cout << "\t\tVendor: " << s << std::endl;
            device.getInfo(CL_DEVICE_OPENCL_C_VERSION, &s);
            std::cout << "\t\tVersion: " << s << std::endl;
            int x;
            device.getInfo(CL_DEVICE_MAX_COMPUTE_UNITS, &x);
            std::cout << "\t\tMax. Compute Units: " << x << std::endl;
            size_t size;
            device.getInfo(CL_DEVICE_LOCAL_MEM_SIZE, &size);
            std::cout << "\t\tLocal Memory Size: " << size / 1024 << " KB" << std::endl;
            device.getInfo(CL_DEVICE_GLOBAL_MEM_SIZE, &size);
            std::cout << "\t\tGlobal Memory Size: " << size / (1024 * 1024) << " MB" << std::endl;
            device.getInfo(CL_DEVICE_MAX_MEM_ALLOC_SIZE, &size);
            std::cout << "\t\tMax Alloc Size: " << size / (1024 * 1024) << " MB" << std::endl;
            device.getInfo(CL_DEVICE_MAX_WORK_GROUP_SIZE, &size);
            std::cout << "\t\tMax Work-group Total Size: " << size << std::endl;
            std::vector<size_t> d;
            device.getInfo(CL_DEVICE_MAX_WORK_ITEM_SIZES, &d);
            std::cout << "\t\tMax Work-group Dims: (";
            for(size_t dd : d){
                std::cout << dd << " ";
            }
            std::cout << ")" << std::endl;
            device.getInfo(CL_DRIVER_VERSION, &s);
            std::cout << "\t\tDriver version: "<< s << std::endl;
            device.getInfo(CL_DEVICE_ADDRESS_BITS, &size);
            std::cout << "\t\tMax bits for work size variable: "<< size << std::endl;
        }
    }

}


void handleError(cl_int status,std::string text) {
    if (status != CL_SUCCESS) {
        std::cout << " Error " << text<< std::endl;
        std::cout << int(status)<< std::endl;
        exit(1);
    }else{
        //std::cout << " okay " << text<< std::endl;
    }
}


void gpuKeyToSHA512(uint8_t * input, uint8_t * output,uint64_t size) {
    cl_int status = CL_SUCCESS;
    std::vector<cl::Platform> platforms;
    status = cl::Platform::get(&platforms);
    handleError(status,"1");
    std::vector<cl::Device> devices;
    status = platforms[1].getDevices(CL_DEVICE_TYPE_ALL,&devices);
    handleError(status,"2");
    cl::Context context(devices[0]);
    cl::CommandQueue queue = cl::CommandQueue(context,devices[0]);
    cl::Buffer keyBuffer(context,CL_MEM_READ_WRITE,sizeof(uint8_t)*32*size);
    cl::Buffer shaBuffer(context,CL_MEM_READ_WRITE,sizeof(uint8_t)*64*size);

    std::string kernel_string = gpuGetStringFromFile("sha512.cl");
    cl::Program::Sources source;
    source.push_back({kernel_string.c_str(),kernel_string.length()});
    cl::Program program(context,source);
    if(program.build({devices[0]})!=CL_SUCCESS){
        std::cout<<" Error building: "<<program.getBuildInfo<CL_PROGRAM_BUILD_LOG>(devices[0])<<"\n";
        exit(1);
    }


    cl::Kernel kernelsha = cl::Kernel(program,"kernel_sha512");

   // status = queue.enqueueWriteBuffer(shaBuffer,CL_TRUE,0,sizeof(uint8_t)*64,input);
   // handleError(status,"4");

    //cl::Kernel kernelsha = cl::Kernel(program,"hash_main");
    /*
    size_t offset=0;
    if((size % 1024)!=0){
        raise(666);
    }
    while(size > 1024) {
        status = queue.enqueueWriteBuffer(keyBuffer, CL_TRUE, 0, sizeof(uint8_t) * 32 * 1024, (input + offset * 32));
        handleError(status, "3");

        kernelsha.setArg(0, keyBuffer);
        kernelsha.setArg(1, shaBuffer);
        status = queue.enqueueNDRangeKernel(kernelsha, cl::NullRange, cl::NDRange(1024));
        handleError(status, "5");

        status = queue.enqueueReadBuffer(shaBuffer, CL_TRUE, 0, sizeof(uint8_t) * 64 * 1024, (output + offset * 64));
        handleError(status, "6");
        size -= 1024;
        offset++;
    }
     */

    status = queue.enqueueWriteBuffer(keyBuffer, CL_TRUE, 0, sizeof(uint8_t) * 32 * size, input );
    handleError(status, "3");
    kernelsha.setArg(0, keyBuffer);
    kernelsha.setArg(1, shaBuffer);
    status = queue.enqueueNDRangeKernel(kernelsha, cl::NullRange, cl::NDRange(size));
    handleError(status, "5");
    status = queue.finish();
    handleError(status,"fin");
    status = queue.enqueueReadBuffer(shaBuffer, CL_TRUE, 0, sizeof(uint8_t) * 64 * size, output);
    handleError(status, "6");

/*
    if (status != CL_SUCCESS){
        std::cout<<" Error";
        exit(1);
    }
    */
}
