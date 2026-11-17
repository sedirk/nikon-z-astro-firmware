// Fixed service session for local backup of CAL38 and ID35, two matching reads.
// Allowlist: 94fd/F001 enter, 94ff/F029 read, 94fd/F002 leave. No data-to-device.
// Entry reloads configuration into RAM and stops live view; leave restores state.
#define Z6_CAL_LIBRARY
#include "z6_wpd_cal_probe.cpp"
#include <array>

class CalibrationSession {
public:
    ComPtr<IPortableDevice> device;
    std::ofstream journal;
    std::wstring context;
    ULONG response=0;
    std::vector<ULONG> params;
    bool end_attempted=false,entry_attempted=false,exit_attempted=false,entered=false,exited=false;
    unsigned reads=0;
    explicit CalibrationSession(const std::filesystem::path& dir):journal(dir/L"events.jsonl",std::ios::binary){}
    void record(const std::string& s){journal<<s<<'\n';journal.flush();std::cout<<s<<std::endl;}
    ComPtr<IPortableDeviceValues> send(const char* stage,IPortableDeviceValues* cmd) {
        ComPtr<IPortableDeviceValues> reply;HRESULT hr=device->SendCommand(0,cmd,&reply),ch=E_FAIL;
        ULONG code=0;std::vector<ULONG> p;
        if(reply){reply->GetErrorValue(WPD_PROPERTY_COMMON_HRESULT,&ch);
            reply->GetUnsignedIntegerValue(WPD_PROPERTY_MTP_EXT_RESPONSE_CODE,&code);p=response_params(reply.Get());
            PWSTR w=nullptr;if(SUCCEEDED(reply->GetStringValue(WPD_PROPERTY_MTP_EXT_TRANSFER_CONTEXT,&w))){context=w?w:L"";CoTaskMemFree(w);}}
        if(code){response=code;params=p;}
        std::ostringstream s;s<<"{\"stage\":"<<quote(stage)<<",\"send_hresult\":"<<quote(hx(hr))<<",\"command_hresult\":"<<quote(hx(ch))
            <<",\"ptp_response\":"<<quote(hx(code))<<",\"params\":[";
        for(size_t i=0;i<p.size();++i){if(i)s<<',';s<<quote(hx(p[i]));}s<<"]}";record(s.str());
        check(hr,stage);check(ch,stage);return reply;
    }
    ComPtr<IPortableDeviceValues> command(bool data_in,const std::array<ULONG,5>& p) {
        if(data_in){
            if(p[0]!=0xf029 || p[3]>1 || p[4] || !p[2] || p[2]>16384)throw std::runtime_error("Read allowlist rejected");
            ULONG cap=p[3]==0?0x168000:0xd8000;
            if(p[1]>cap || p[2]>cap-p[1])throw std::runtime_error("Read bounds rejected");
        }else if((p[0]!=0xf001 && p[0]!=0xf002)||p[1]||p[2]||p[3]||p[4])throw std::runtime_error("Mode allowlist rejected");
        auto cmd=request(data_in?WPD_COMMAND_MTP_EXT_EXECUTE_COMMAND_WITH_DATA_TO_READ:WPD_COMMAND_MTP_EXT_EXECUTE_COMMAND_WITHOUT_DATA_PHASE);
        // WPD requires its read/write command channel for state-changing,
        // no-data commands. Data retrieval still uses FILE_READ_ACCESS.
        if(!data_in)check(cmd->SetUnsignedIntegerValue(WPD_API_OPTION_IOCTL_ACCESS,FILE_READ_ACCESS|FILE_WRITE_ACCESS),"Mode IOCTL access");
        check(cmd->SetUnsignedIntegerValue(WPD_PROPERTY_MTP_EXT_OPERATION_CODE,data_in?0x94ff:0x94fd),"Opcode");
        ComPtr<IPortableDevicePropVariantCollection> c;
        check(CoCreateInstance(CLSID_PortableDevicePropVariantCollection,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&c)),"Parameters");
        for(ULONG n:p){PROPVARIANT v;PropVariantInit(&v);v.vt=VT_UI4;v.ulVal=n;check(c->Add(&v),"Parameter");PropVariantClear(&v);}
        check(cmd->SetIPortableDevicePropVariantCollectionValue(WPD_PROPERTY_MTP_EXT_OPERATION_PARAMS,c.Get()),"Set parameters");
        std::ostringstream s;s<<"{\"request\":"<<quote(data_in?"0x94ff":"0x94fd")<<",\"params\":[";
        for(size_t i=0;i<p.size();++i){if(i)s<<',';s<<p[i];}s<<"]}";record(s.str());
        return cmd;
    }
    void finish(){
        if(context.empty()||end_attempted)return;
        end_attempted=true;auto p=request(WPD_COMMAND_MTP_EXT_END_DATA_TRANSFER);
        check(p->SetStringValue(WPD_PROPERTY_MTP_EXT_TRANSFER_CONTEXT,context.c_str()),"End context");send("end",p.Get());
        context.clear();
    }
    void require_success(){if(response!=0x2001 || params.size()!=5 || params[0]!=0x2001)throw std::runtime_error("PTP or inner status rejected");}
    void mode(bool enter){
        if(enter){if(entry_attempted)throw std::runtime_error("No repeated entry");entry_attempted=true;}
        else {if(exit_attempted)return;exit_attempted=true;}
        response=0;params.clear();auto p=command(false,{enter?0xf001ul:0xf002ul,0,0,0,0});
        send(enter?"enter_service":"leave_service",p.Get());require_success();
        if(enter)entered=true;else{exited=true;entered=false;}
    }
    std::vector<BYTE> read(ULONG selector,ULONG offset,ULONG count,bool expect_closed=false){
        if(!expect_closed && !entered)throw std::runtime_error("Read requires successful entry");
        context.clear();end_attempted=false;response=0;params.clear();std::vector<BYTE> data;
        auto cmd=command(true,{0xf029,offset,count,selector,0});auto reply=send("execute_read",cmd.Get());++reads;
        try{
            if(!context.empty()){
                ULONGLONG total=0;check(reply->GetUnsignedLargeIntegerValue(WPD_PROPERTY_MTP_EXT_TRANSFER_TOTAL_DATA_SIZE,&total),"Total size");
                if(total>count)throw std::runtime_error("Unexpected oversized response");
                while(data.size()<total){
                    DWORD want=static_cast<DWORD>(total-data.size());std::vector<BYTE> buffer(want);
                    auto p=request(WPD_COMMAND_MTP_EXT_READ_DATA);
                    check(p->SetStringValue(WPD_PROPERTY_MTP_EXT_TRANSFER_CONTEXT,context.c_str()),"Read context");
                    check(p->SetUnsignedIntegerValue(WPD_PROPERTY_MTP_EXT_TRANSFER_NUM_BYTES_TO_READ,want),"Read size");
                    check(p->SetBufferValue(WPD_PROPERTY_MTP_EXT_TRANSFER_DATA,buffer.data(),want),"Read buffer");
                    auto r=send("read",p.Get());DWORD got=0,n=0;BYTE* b=nullptr;
                    check(r->GetUnsignedIntegerValue(WPD_PROPERTY_MTP_EXT_TRANSFER_NUM_BYTES_READ,&got),"Read count");
                    check(r->GetBufferValue(WPD_PROPERTY_MTP_EXT_TRANSFER_DATA,&b,&n),"Read bytes");
                    if(!got||got>want||n<got){CoTaskMemFree(b);throw std::runtime_error("Invalid read length");}
                    data.insert(data.end(),b,b+got);CoTaskMemFree(b);
                }
                finish();
            }
        }catch(...){try{finish();}catch(...){}throw;}
        if(expect_closed){if(response!=0xa004 || !data.empty())throw std::runtime_error("Service gate did not close");}
        else {require_success();if(data.size()!=count)throw std::runtime_error("Short calibration read");}
        return data;
    }
    void open(){
        ComPtr<IPortableDeviceManager> manager;check(CoCreateInstance(CLSID_PortableDeviceManager,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&manager)),"Manager");
        DWORD n=0;check(manager->GetDevices(nullptr,&n),"Device count");if(n>128)throw std::runtime_error("Device count limit");
        std::vector<PWSTR> ids(n,nullptr);if(n)check(manager->GetDevices(ids.data(),&n),"Device list");std::vector<std::wstring> matches;
        for(PWSTR id:ids)if(id){std::wstring s=id;std::transform(s.begin(),s.end(),s.begin(),towupper);
            if(s.find(L"VID_04B0")!=std::wstring::npos&&s.find(L"PID_0443")!=std::wstring::npos)matches.emplace_back(id);CoTaskMemFree(id);}
        if(matches.size()!=1)throw std::runtime_error("Require exactly one Z6");
        check(CoCreateInstance(CLSID_PortableDeviceFTM,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&device)),"Device");
        auto client=values();check(client->SetStringValue(WPD_CLIENT_NAME,L"Z6 fixed calibration backup session"),"Client");
        check(client->SetUnsignedIntegerValue(WPD_CLIENT_DESIRED_ACCESS,GENERIC_READ|GENERIC_WRITE),"Session command access");
        check(client->SetUnsignedIntegerValue(WPD_CLIENT_SECURITY_QUALITY_OF_SERVICE,SECURITY_IMPERSONATION),"Security");
        check(device->Open(matches[0].c_str(),client.Get()),"Open");
        ComPtr<IPortableDeviceContent> content;check(device->Content(&content),"Content");
        ComPtr<IPortableDeviceProperties> properties;check(content->Properties(&properties),"Properties");
        ComPtr<IPortableDeviceKeyCollection> keys;check(CoCreateInstance(CLSID_PortableDeviceKeyCollection,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&keys)),"Keys");
        check(keys->Add(WPD_DEVICE_MODEL),"Model");check(keys->Add(WPD_DEVICE_FIRMWARE_VERSION),"Version");
        ComPtr<IPortableDeviceValues> identity;check(properties->GetValues(WPD_DEVICE_OBJECT_ID,keys.Get(),&identity),"Identity");
        auto model=string_prop(identity.Get(),WPD_DEVICE_MODEL),fw=string_prop(identity.Get(),WPD_DEVICE_FIRMWARE_VERSION);
        record("{\"model\":"+quote(model)+",\"firmware\":"+quote(fw)+"}");
        if(model!="Z 6"||fw!="V3.80")throw std::runtime_error("Wrong body/version");
    }
};
int wmain(int argc,wchar_t** argv){
    const bool self_test=argc==3 && std::wstring(argv[1])==L"--self-test";
    if(argc!=3 || (!self_test && std::wstring(argv[1])!=L"--read-targets")){std::cerr<<"Usage: z6_wpd_cal_session --read-targets|--self-test NEW_DIRECTORY\n";return 2;}
    std::filesystem::path out=argv[2];if(std::filesystem::exists(out)){std::cerr<<"Output exists\n";return 2;}
    std::filesystem::create_directories(out);CalibrationSession s(out);
    HRESULT init=CoInitializeEx(nullptr,COINIT_MULTITHREADED);if(FAILED(init))return 2;
    if(self_test){
        struct Case{bool read;std::array<ULONG,5> p;bool allowed;};
        const Case cases[]={
            {true,{0xf029,0,32,0,0},true},{true,{0xf029,0x167fff,1,0,0},true},
            {true,{0xf029,0xd7fff,1,1,0},true},{true,{0xf029,0x168000,1,0,0},false},
            {true,{0xf029,0xffffffff,32,0,0},false},{true,{0xf029,0,0,0,0},false},
            {true,{0xf029,0,16385,0,0},false},{true,{0xf029,0,32,2,0},false},
            {true,{0xf02a,0,32,0,0},false},{true,{0xf029,0,32,0,1},false},
            {false,{0xf001,0,0,0,0},true},{false,{0xf002,0,0,0,0},true},
            {false,{0xf002,1,0,0,0},false},{false,{0xf02a,0,0,0,0},false}};
        bool pass=true;unsigned count=0;
        for(const auto& c:cases){bool allowed=false;try{s.command(c.read,c.p);allowed=true;}catch(const std::exception&){}
            pass=pass&&(allowed==c.allowed);++count;}
        std::string result="{\"ok\":"+std::string(pass?"true":"false")+",\"cases\":"+std::to_string(count)+",\"camera_opened\":false,\"commands_sent\":0}";
        std::ofstream f(out/L"result.json",std::ios::binary);f<<result<<'\n';s.record(result);CoUninitialize();return pass?0:1;
    }
    bool ok=false,gate_closed=false;std::string error;HRESULT closed=S_OK;
    s.record("{\"scope\":\"F001 RAM reload and service entry; F029 two matching backups; F002 exit\",\"firmware_or_calibration_write_requested\":false}");
    try{
        s.open();s.mode(true);
        for(ULONG selector=0;selector<2;++selector){
            const ULONG total=selector==0?0x168000:0xd8000;
            const std::wstring name=selector==0?L"CAL38.bin":L"ID35.bin";
            std::ofstream first(out/name,std::ios::binary);if(!first)throw std::runtime_error("Cannot save backup");
            for(ULONG offset=0;offset<total;offset+=16384){
                ULONG count=std::min<ULONG>(16384,total-offset);
                auto a=s.read(selector,offset,count);auto b=s.read(selector,offset,count);
                if(a!=b)throw std::runtime_error("Repeated reads differ");
                first.write(reinterpret_cast<const char*>(a.data()),a.size());first.flush();if(!first)throw std::runtime_error("Backup write failed");
                s.record("{\"verified_chunk\":true,\"selector\":"+std::to_string(selector)+",\"offset\":"+std::to_string(offset)+",\"length\":"+std::to_string(count)+"}");
            }
        }
        s.mode(false);s.read(0,0,32,true);gate_closed=true;ok=true;
    }catch(const std::exception& e){error=e.what();try{s.finish();}catch(const std::exception& x){error+="; end: ";error+=x.what();}}
    if(s.entry_attempted&&!s.exit_attempted){try{s.mode(false);}catch(const std::exception& x){error+="; exit: ";error+=x.what();ok=false;}}
    if(s.device){closed=s.device->Close();s.device.Reset();if(FAILED(closed)){ok=false;error+="; Close failed";}}
    CoUninitialize();
    std::ostringstream r;r<<"{\"ok\":"<<(ok?"true":"false")<<",\"error\":"<<quote(error)<<",\"entry_attempted\":"<<(s.entry_attempted?"true":"false")
        <<",\"exit_attempted\":"<<(s.exit_attempted?"true":"false")<<",\"exit_succeeded\":"<<(s.exited?"true":"false")<<",\"gate_closed\":"<<(gate_closed?"true":"false")
        <<",\"read_commands\":"<<s.reads<<",\"close_hresult\":"<<quote(hx(closed))<<",\"firmware_or_calibration_write_requested\":false}";
    s.record(r.str());std::ofstream result(out/L"result.json",std::ios::binary);result<<r.str()<<'\n';return ok?0:1;
}
