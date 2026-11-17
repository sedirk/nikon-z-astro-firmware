// Narrow independent Nikon 0x46/14-bit lossless unpacker for research checks.
// Published Huffman format reference: LibRaw 0.22.2, decoders_dcraw.cpp,
// nikon_load_raw (LibRaw LGPL-2.1/CDDL source). This implementation performs
// canonical Huffman + same-colour prediction only: no curve, clamp or filter.
// Input offsets, dimensions and four initial predictors are supplied by a
// bounded TIFF reader. Decoded little-endian uint16 pixels stream to stdout.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <vector>

struct Bits {
    const std::vector<uint8_t>& input;
    size_t pos=0; uint64_t buffer=0; unsigned available=0;
    unsigned get(unsigned n) {
        if (!n) return 0;
        while (available<n) {
            if(pos>=input.size()) throw std::runtime_error("short compressed stream");
            buffer=(buffer<<8)|input[pos++];available+=8;
        }
        available-=n;
        unsigned out=(buffer>>available)&((1u<<n)-1);
        buffer&=(1ull<<available)-1;
        return out;
    }
};

int main(int argc,char** argv) {
    try {
        if(argc!=10) throw std::runtime_error("file offset size width height pred00 pred01 pred10 pred11");
        auto num=[](const char* x){char* end=nullptr;auto n=std::strtoull(x,&end,10);if(!end||*end)throw std::runtime_error("bad number");return n;};
        const auto offset=num(argv[2]),size=num(argv[3]),width=num(argv[4]),height=num(argv[5]);
        if(width>10000||height>10000||!width||!height||size>256*1024*1024) throw std::runtime_error("bounds");
        int vertical[2][2]={{int(num(argv[6])),int(num(argv[7]))},{int(num(argv[8])),int(num(argv[9]))}};
        FILE* f=std::fopen(argv[1],"rb");if(!f)throw std::runtime_error("open");
        if(std::fseek(f,long(offset),SEEK_SET))throw std::runtime_error("seek");
        std::vector<uint8_t> input(size);if(std::fread(input.data(),1,size,f)!=size)throw std::runtime_error("read");std::fclose(f);
        const unsigned counts[16]={0,1,4,2,2,3,1,2,0,0,0,0,0,0,0,0};
        const unsigned symbols[15]={7,6,8,5,9,4,10,3,11,12,2,0,1,13,14};
        unsigned first[17]={},start[17]={},code=0,index=0;
        for(unsigned len=1;len<=16;++len){first[len]=code;start[len]=index;index+=counts[len-1];code=(code+counts[len-1])<<1;}
        if(index!=15)throw std::runtime_error("tree");
        Bits bits{input};std::vector<uint8_t> row(width*2);int horizontal[2]={};
        for(unsigned y=0;y<height;++y){
            for(unsigned x=0;x<width;++x){
                unsigned symbol=99,c=0;
                for(unsigned len=1;len<=16;++len){
                    c=(c<<1)|bits.get(1);
                    if(c>=first[len] && c-first[len]<counts[len-1]){symbol=symbols[start[len]+c-first[len]];break;}
                }
                if(symbol>14)throw std::runtime_error("symbol");
                int difference=int(bits.get(symbol));
                if(symbol && difference<(1<<(symbol-1)))difference-=(1<<symbol)-1;
                if(x<2){vertical[y&1][x]+=difference;horizontal[x]=vertical[y&1][x];}
                else horizontal[x&1]+=difference;
                int value=horizontal[x&1];if(value<0||value>16383)throw std::runtime_error("range");
                row[x*2]=value&255;row[x*2+1]=value>>8;
            }
            if(std::fwrite(row.data(),1,row.size(),stdout)!=row.size())throw std::runtime_error("output");
        }
        if(std::fflush(stdout))throw std::runtime_error("flush");
        std::fprintf(stderr,"decoded=%llu consumed_bytes=%zu strip_bytes=%llu\n",width*height,bits.pos,size);
        return 0;
    }catch(const std::exception& e){std::fprintf(stderr,"%s\n",e.what());return 1;}
}
