// Bounded F029 calibration read probe. Exactly one 32-byte CAL38 read.
// No service-entry command, data-to-device command, capture or firmware update.
// Reuse audited identity-reader COM helpers; its renamed entry is never called.
#define wmain z6_inventory_entry_unused
#include "z6_wpd_inventory.cpp"
#undef wmain

static ComPtr<IPortableDeviceValues> request(REFPROPERTYKEY key) {
    auto p=values();
    check(p->SetGuidValue(WPD_PROPERTY_COMMON_COMMAND_CATEGORY,key.fmtid),"Category");
    check(p->SetUnsignedIntegerValue(WPD_PROPERTY_COMMON_COMMAND_ID,key.pid),"Command id");
    check(p->SetUnsignedIntegerValue(WPD_API_OPTION_IOCTL_ACCESS,FILE_READ_ACCESS),"Read IOCTL");
    return p;
}
static std::vector<ULONG> response_params(IPortableDeviceValues* p) {
    std::vector<ULONG> result;ComPtr<IPortableDevicePropVariantCollection> c;
    if(FAILED(p->GetIPortableDevicePropVariantCollectionValue(WPD_PROPERTY_MTP_EXT_RESPONSE_PARAMS,&c)))return result;
    DWORD n=0;check(c->GetCount(&n),"Response count");if(n>5)throw std::runtime_error("Excess response parameters");
    for(DWORD i=0;i<n;++i){PROPVARIANT v;PropVariantInit(&v);check(c->GetAt(i,&v),"Response parameter");
        if(v.vt!=VT_UI4){PropVariantClear(&v);throw std::runtime_error("Non-UI4 response");}
        result.push_back(v.ulVal);PropVariantClear(&v);}
    return result;
}
#ifndef Z6_CAL_LIBRARY
int wmain(int argc,wchar_t** argv) {
    if(argc!=3 || std::wstring(argv[1])!=L"--probe"){
        std::cerr<<"Usage: z6_wpd_cal_probe --probe NEW_OUTPUT_DIRECTORY\n";return 2;
    }
    std::filesystem::path out=argv[2];
    if(std::filesystem::exists(out)){std::cerr<<"Output exists\n";return 2;}
    std::filesystem::create_directories(out);
    std::ofstream log(out/L"events.jsonl",std::ios::binary);
    auto record=[&](const std::string& line){log<<line<<'\n';log.flush();std::cout<<line<<std::endl;};
    record("{\"scope\":\"one F029 CAL38 read, offset 0, length 32; no service entry\",\"params\":[61481,0,32,0,0]}");
    HRESULT init=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    if(FAILED(init)){record("{\"error\":\"CoInitializeEx failed\"}");return 2;}
    ComPtr<IPortableDevice> device;std::wstring context;bool end_attempted=false,command_attempted=false;
    bool ok=false;std::string error,outcome="not_executed";HRESULT close_hr=S_OK;
    ULONG response=0;std::vector<ULONG> params;std::vector<BYTE> data;
    auto send=[&](const char* stage,IPortableDeviceValues* p){
        ComPtr<IPortableDeviceValues> reply;HRESULT hr=device->SendCommand(0,p,&reply),inner=E_FAIL;
        if(reply)reply->GetErrorValue(WPD_PROPERTY_COMMON_HRESULT,&inner);
        ULONG code=0;std::vector<ULONG> ps;
        if(reply){reply->GetUnsignedIntegerValue(WPD_PROPERTY_MTP_EXT_RESPONSE_CODE,&code);ps=response_params(reply.Get());}
        std::ostringstream s;s<<"{\"stage\":"<<quote(stage)<<",\"send_hresult\":"<<quote(hx(hr))
            <<",\"command_hresult\":"<<quote(hx(inner))<<",\"ptp_response\":"<<quote(hx(code))<<",\"response_params\":[";
        for(size_t i=0;i<ps.size();++i){if(i)s<<',';s<<quote(hx(ps[i]));}s<<"]}";record(s.str());
        if(code){response=code;params=ps;}
        // Capture the transfer context even on an error, so cleanup can finish it.
        if(reply){PWSTR w=nullptr;if(SUCCEEDED(reply->GetStringValue(WPD_PROPERTY_MTP_EXT_TRANSFER_CONTEXT,&w))){context=w?w:L"";CoTaskMemFree(w);}}
        check(hr,stage);check(inner,stage);return reply;
    };
    auto finish=[&](){
        if(context.empty()||end_attempted)return;
        end_attempted=true;auto p=request(WPD_COMMAND_MTP_EXT_END_DATA_TRANSFER);
        check(p->SetStringValue(WPD_PROPERTY_MTP_EXT_TRANSFER_CONTEXT,context.c_str()),"End context");
        send("end",p.Get());
    };
    try {
        ComPtr<IPortableDeviceManager> manager;
        check(CoCreateInstance(CLSID_PortableDeviceManager,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&manager)),"Manager");
        DWORD count=0;check(manager->GetDevices(nullptr,&count),"Count devices");
        if(count>128)throw std::runtime_error("Too many devices");
        std::vector<PWSTR> ids(count,nullptr);if(count)check(manager->GetDevices(ids.data(),&count),"Devices");
        std::vector<std::wstring> matches;
        for(PWSTR id:ids){if(id){std::wstring upper=id;std::transform(upper.begin(),upper.end(),upper.begin(),towupper);
            if(upper.find(L"VID_04B0")!=std::wstring::npos&&upper.find(L"PID_0443")!=std::wstring::npos)matches.emplace_back(id);CoTaskMemFree(id);}}
        if(matches.size()!=1)throw std::runtime_error("Require exactly one Nikon Z6 VID_04B0/PID_0443");
        check(CoCreateInstance(CLSID_PortableDeviceFTM,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&device)),"Device");
        auto client=values();check(client->SetStringValue(WPD_CLIENT_NAME,L"Z6 bounded calibration read probe"),"Client name");
        check(client->SetUnsignedIntegerValue(WPD_CLIENT_DESIRED_ACCESS,GENERIC_READ),"Read access");
        check(client->SetUnsignedIntegerValue(WPD_CLIENT_SECURITY_QUALITY_OF_SERVICE,SECURITY_IMPERSONATION),"Impersonation");
        check(device->Open(matches[0].c_str(),client.Get()),"Open");
        ComPtr<IPortableDeviceContent> content;check(device->Content(&content),"Content");
        ComPtr<IPortableDeviceProperties> props;check(content->Properties(&props),"Properties");
        ComPtr<IPortableDeviceKeyCollection> keys;
        check(CoCreateInstance(CLSID_PortableDeviceKeyCollection,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&keys)),"Keys");
        check(keys->Add(WPD_DEVICE_MODEL),"Model key");check(keys->Add(WPD_DEVICE_FIRMWARE_VERSION),"Firmware key");
        ComPtr<IPortableDeviceValues> identity;check(props->GetValues(WPD_DEVICE_OBJECT_ID,keys.Get(),&identity),"Identity");
        auto model=string_prop(identity.Get(),WPD_DEVICE_MODEL),fw=string_prop(identity.Get(),WPD_DEVICE_FIRMWARE_VERSION);
        record("{\"model\":"+quote(model)+",\"firmware\":"+quote(fw)+"}");
        if(model!="Z 6" || fw!="V3.80")throw std::runtime_error("Identity mismatch; no vendor operation sent");
        auto start=request(WPD_COMMAND_MTP_EXT_EXECUTE_COMMAND_WITH_DATA_TO_READ);
        check(start->SetUnsignedIntegerValue(WPD_PROPERTY_MTP_EXT_OPERATION_CODE,0x94ff),"Opcode");
        ComPtr<IPortableDevicePropVariantCollection> args;
        check(CoCreateInstance(CLSID_PortableDevicePropVariantCollection,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&args)),"Params");
        for(ULONG x:{0xf029ul,0ul,32ul,0ul,0ul}){PROPVARIANT v;PropVariantInit(&v);v.vt=VT_UI4;v.ulVal=x;check(args->Add(&v),"Add param");PropVariantClear(&v);}
        check(start->SetIPortableDevicePropVariantCollectionValue(WPD_PROPERTY_MTP_EXT_OPERATION_PARAMS,args.Get()),"Set params");
        command_attempted=true;record("{\"executing\":\"0x94ff\",\"subcommand\":\"0xf029\"}");
        auto reply=send("execute_read",start.Get());
        if(!context.empty()){
            ULONGLONG total=0;check(reply->GetUnsignedLargeIntegerValue(WPD_PROPERTY_MTP_EXT_TRANSFER_TOTAL_DATA_SIZE,&total),"Total size");
            record("{\"advertised_data_size\":"+std::to_string(total)+"}");
            if(total>32)throw std::runtime_error("Data larger than bounded read");
            while(data.size()<total){
                DWORD want=static_cast<DWORD>(total-data.size());std::vector<BYTE> buf(want);
                auto read=request(WPD_COMMAND_MTP_EXT_READ_DATA);
                check(read->SetStringValue(WPD_PROPERTY_MTP_EXT_TRANSFER_CONTEXT,context.c_str()),"Read context");
                check(read->SetUnsignedIntegerValue(WPD_PROPERTY_MTP_EXT_TRANSFER_NUM_BYTES_TO_READ,want),"Read size");
                check(read->SetBufferValue(WPD_PROPERTY_MTP_EXT_TRANSFER_DATA,buf.data(),want),"Read buffer");
                auto rr=send("read",read.Get());DWORD got=0;check(rr->GetUnsignedIntegerValue(WPD_PROPERTY_MTP_EXT_TRANSFER_NUM_BYTES_READ,&got),"Bytes read");
                BYTE* p=nullptr;DWORD n=0;check(rr->GetBufferValue(WPD_PROPERTY_MTP_EXT_TRANSFER_DATA,&p,&n),"Data buffer");
                if(got==0||got>want||n<got){CoTaskMemFree(p);throw std::runtime_error("Invalid read length");}
                data.insert(data.end(),p,p+got);CoTaskMemFree(p);
            }
            finish();
        }
        if(response==0xa004 && data.empty()){outcome="service_gate_closed";ok=true;}
        else if(response==0x2001 && params.size()==5 && params[0]==0x2001 && data.size()==32){
            outcome="cal38_prefix_read";ok=true;std::ofstream binary(out/L"cal38-offset0-length32.bin",std::ios::binary);
            binary.write(reinterpret_cast<const char*>(data.data()),data.size());if(!binary)throw std::runtime_error("Saving read failed");
        } else throw std::runtime_error("Unexpected response or inner status; see events");
    } catch(const std::exception& e){error=e.what();ok=false;
        try{finish();}catch(const std::exception& cleanup){error+="; cleanup: ";error+=cleanup.what();}
        if(response==0xa004 && data.empty()){outcome="service_gate_closed";ok=true;}
    }
    if(device){close_hr=device->Close();device.Reset();if(FAILED(close_hr)){ok=false;error+="; Close failed";}}
    CoUninitialize();
    std::ostringstream s;s<<"{\"ok\":"<<(ok?"true":"false")<<",\"outcome\":"<<quote(outcome)<<",\"error\":"<<quote(error)
        <<",\"command_attempted\":"<<(command_attempted?"true":"false")<<",\"service_entered\":false,\"write_requested\":false,\"bytes_read\":"<<data.size()
        <<",\"end_attempted\":"<<(end_attempted?"true":"false")<<",\"close_hresult\":"<<quote(hx(close_hr))<<"}";
    record(s.str());std::ofstream summary(out/L"result.json",std::ios::binary);summary<<s.str()<<'\n';return ok?0:1;
}
#endif
