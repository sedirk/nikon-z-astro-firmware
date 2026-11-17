"""Create isolated modified4 review tools, preserving earlier reviewed tools."""
from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parents[2];T=ROOT/'tools/fw'
created=[]
def fork(source,target,replacements):
    data=(T/source).read_text(encoding='utf8')
    for old,new in replacements:
        if old not in data:raise ValueError((source,old))
        data=data.replace(old,new)
    with (T/target).open('x',encoding='utf8',newline='\n') as f:f.write(data)
    created.append(dict(path='tools/fw/'+target,sha256=hashlib.sha256((T/target).read_bytes()).hexdigest()))

fork('verify_spatial_preflash_kit.py','verify_front_preflash_kit.py',[
 ('modified3','modified4'),('modified2','modified3'),
 ("'test':'a8ec90a9b55b2eefcd46e13b0f6acd0b7aa1bc4d9d127d701dee89154b8b04bd'","'test':'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'"),
 ('6790186e7e088ae7c504677be052aecdbf3868616207bfda5606b36d37149038','a8ec90a9b55b2eefcd46e13b0f6acd0b7aa1bc4d9d127d701dee89154b8b04bd'),
 ('01_TEST_MODIFIED3','01_TEST_MODIFIED4'),('02_BACK_TO_MODIFIED2','02_BACK_TO_MODIFIED3'),
 ("(0x10197876,'4078','0020'))","(0x10197876,'4078','0020'),(0x100f64b4,'90f85902','4ff00200'))"),
 ("('modified3',6),('test',9)","('modified3',9),('test',10)"),
 ("manifest['schema']==3","manifest['schema']==4")])
fork('probe_spatial_preflash_updater.py','probe_front_preflash_updater.py',[
 ('modified3','modified4'),('modified2','modified3'),
 ('review_spatial_preflash','review_front_preflash'),('verify_spatial_preflash_kit','verify_front_preflash_kit'),
 ('0x177868','0xd64b4')])
fork('test_spatial_preflash_verifier.py','test_front_preflash_verifier.py',[
 ('verify_spatial_preflash_kit','verify_front_preflash_kit'),('review_spatial_preflash','review_front_preflash'),('0x177868','0xd64b4')])
print(json.dumps(created,indent=2))
