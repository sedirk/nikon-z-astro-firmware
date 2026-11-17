// Read only: device identity and advertised vendor opcodes via Windows WPD.
// No vendor opcode execution, capture, service mode, file deletion or firmware write.
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <portabledeviceapi.h>
#include <portabledevicetypes.h>
#include <portabledevice.h>
#include <WpdMtpExtensions.h>
#include <wrl/client.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using Microsoft::WRL::ComPtr;
static std::string hx(unsigned long x) { std::ostringstream s; s<<"0x"<<std::hex<<x; return s.str(); }
static void check(HRESULT h,const char* where) { if(FAILED(h))throw std::runtime_error(std::string(where)+": "+hx(h)); }
static std::string utf8(const std::wstring& w) {
    if(w.empty())return {}; int n=WideCharToMultiByte(CP_UTF8,0,w.data(),(int)w.size(),nullptr,0,nullptr,nullptr);
    std::string s(n,'\0'); WideCharToMultiByte(CP_UTF8,0,w.data(),(int)w.size(),s.data(),n,nullptr,nullptr); return s;
}
static std::string quote(const std::string& v) {
    std::ostringstream s;s<<'"';for(unsigned char c:v) {if(c=='"'||c=='\\')s<<'\\'<<c;else if(c<32)s<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<(int)c;else s<<c;}s<<'"';return s.str();
}
static ComPtr<IPortableDeviceValues> values() {
    ComPtr<IPortableDeviceValues> p;check(CoCreateInstance(CLSID_PortableDeviceValues,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&p)),"Create values");return p;
}
static std::string string_prop(IPortableDeviceValues* p,REFPROPERTYKEY key) {
    PWSTR w=nullptr;HRESULT h=p->GetStringValue(key,&w);if(FAILED(h))return std::string("unavailable:")+hx(h);
    std::string s=utf8(w?w:L"");CoTaskMemFree(w);return s;
}
int wmain(int argc,wchar_t** argv) {
    if(argc!=2){std::cerr<<"Usage: z6_wpd_inventory output.json\n";return 2;}
    const std::filesystem::path out=argv[1];if(std::filesystem::exists(out)){std::cerr<<"Output already exists\n";return 2;}
    HRESULT initialized=CoInitializeEx(nullptr,COINIT_MULTITHREADED);if(FAILED(initialized))return 2;
    ComPtr<IPortableDevice> device;std::ostringstream result;int rc=1;
    try {
        ComPtr<IPortableDeviceManager> manager;
        check(CoCreateInstance(CLSID_PortableDeviceManager,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&manager)),"Create manager");
        DWORD count=0;check(manager->GetDevices(nullptr,&count),"Count devices");
        if(count>128)throw std::runtime_error("Unexpected device count");
        std::vector<PWSTR> ids(count,nullptr);if(count)check(manager->GetDevices(ids.data(),&count),"List devices");
        std::vector<std::wstring> selected;
        for(PWSTR id:ids) {if(id){std::wstring s=id;std::transform(s.begin(),s.end(),s.begin(),towupper);
            if(s.find(L"VID_04B0")!=std::wstring::npos && s.find(L"PID_0443")!=std::wstring::npos)selected.emplace_back(id);CoTaskMemFree(id);}}
        if(selected.size()!=1)throw std::runtime_error("Require exactly one Nikon VID_04B0/PID_0443 Z6");
        check(CoCreateInstance(CLSID_PortableDeviceFTM,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&device)),"Create device");
        auto client=values();check(client->SetStringValue(WPD_CLIENT_NAME,L"Z6 read-only identity and opcode inventory"),"Client name");
        check(client->SetUnsignedIntegerValue(WPD_CLIENT_MAJOR_VERSION,1),"Client version");
        check(client->SetUnsignedIntegerValue(WPD_CLIENT_MINOR_VERSION,0),"Client version");
        check(client->SetUnsignedIntegerValue(WPD_CLIENT_REVISION,0),"Client revision");
        check(client->SetUnsignedIntegerValue(WPD_CLIENT_DESIRED_ACCESS,GENERIC_READ),"Read-only access");
        check(client->SetUnsignedIntegerValue(WPD_CLIENT_SECURITY_QUALITY_OF_SERVICE,SECURITY_IMPERSONATION),"Impersonation");
        check(device->Open(selected[0].c_str(),client.Get()),"Open read-only device");
        ComPtr<IPortableDeviceContent> content;check(device->Content(&content),"Content");
        ComPtr<IPortableDeviceProperties> properties;check(content->Properties(&properties),"Properties");
        ComPtr<IPortableDeviceKeyCollection> keys;
        check(CoCreateInstance(CLSID_PortableDeviceKeyCollection,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&keys)),"Create keys");
        check(keys->Add(WPD_DEVICE_MANUFACTURER),"Add manufacturer");check(keys->Add(WPD_DEVICE_MODEL),"Add model");
        check(keys->Add(WPD_DEVICE_FIRMWARE_VERSION),"Add firmware");check(keys->Add(WPD_DEVICE_FRIENDLY_NAME),"Add friendly name");
        ComPtr<IPortableDeviceValues> identity;check(properties->GetValues(WPD_DEVICE_OBJECT_ID,keys.Get(),&identity),"Get identity");
        auto command=values();check(command->SetGuidValue(WPD_PROPERTY_COMMON_COMMAND_CATEGORY,WPD_COMMAND_MTP_EXT_GET_SUPPORTED_VENDOR_OPCODES.fmtid),"Command category");
        check(command->SetUnsignedIntegerValue(WPD_PROPERTY_COMMON_COMMAND_ID,WPD_COMMAND_MTP_EXT_GET_SUPPORTED_VENDOR_OPCODES.pid),"Command id");
        check(command->SetUnsignedIntegerValue(WPD_API_OPTION_IOCTL_ACCESS,FILE_READ_ACCESS),"Read-only IOCTL");
        ComPtr<IPortableDeviceValues> reply;check(device->SendCommand(0,command.Get(),&reply),"Get supported vendor opcodes");
        HRESULT device_hr=E_FAIL;check(reply->GetErrorValue(WPD_PROPERTY_COMMON_HRESULT,&device_hr),"Command HRESULT");check(device_hr,"Vendor opcode query");
        ComPtr<IPortableDevicePropVariantCollection> ops;
        check(reply->GetIPortableDevicePropVariantCollectionValue(WPD_PROPERTY_MTP_EXT_VENDOR_OPERATION_CODES,&ops),"Opcode collection");
        DWORD n=0;check(ops->GetCount(&n),"Opcode count");if(n>4096)throw std::runtime_error("Too many opcodes");
        result<<"{\n  \"ok\": true,\n  \"read_only\": true,\n  \"access\": \"GENERIC_READ\",\n  \"manufacturer\": "<<quote(string_prop(identity.Get(),WPD_DEVICE_MANUFACTURER))
              <<",\n  \"model\": "<<quote(string_prop(identity.Get(),WPD_DEVICE_MODEL))<<",\n  \"firmware\": "<<quote(string_prop(identity.Get(),WPD_DEVICE_FIRMWARE_VERSION))
              <<",\n  \"friendly_name\": "<<quote(string_prop(identity.Get(),WPD_DEVICE_FRIENDLY_NAME))<<",\n  \"vendor_opcodes\": [";
        for(DWORD i=0;i<n;++i){PROPVARIANT v;PropVariantInit(&v);check(ops->GetAt(i,&v),"Opcode item");
            if(v.vt!=VT_UI4){PropVariantClear(&v);throw std::runtime_error("Non-UI4 opcode");}
            if(i)result<<", ";result<<quote(hx(v.ulVal));PropVariantClear(&v);}
        result<<"],\n  \"vendor_opcodes_executed\": [],\n  \"capture_or_flash_requested\": false\n}\n";
        rc=0;
    } catch(const std::exception& e) { result.str("");result<<"{\"ok\":false,\"error\":"<<quote(e.what())<<",\"vendor_opcodes_executed\":[],\"capture_or_flash_requested\":false}\n"; }
    if(device){HRESULT h=device->Close();if(FAILED(h)){std::cerr<<"Close: "<<hx(h)<<"\n";rc=1;}device.Reset();}
    CoUninitialize();std::ofstream f(out,std::ios::binary);if(!f)return 2;f<<result.str();f.close();
    std::cout<<result.str();return rc;
}
