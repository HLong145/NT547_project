"""D5 — mô phỏng độ rộng CI 95% (chỉ do lấy mẫu) của precision/recall/FPR của engine (mức warn) khi đo bằng nhãn vàng.

python -X utf8 -m address_misuse.gold_power

Ước lượng Horvitz–Thompson theo dòng, phân tầng (tầng × cờ engine). Nhãn vàng thật chưa có nên giả định hai tham số:
q = tỉ lệ dương-theo-tác-giả bị nhãn vàng gán âm, r = tỉ lệ dương ẩn trong tầng âm (S1 'vừa', S2 'lạc quan'; pilot: A gán
3/4 mẫu PCD là âm, B gán 1/4 mẫu N1 là dương). So các thiết kế mẫu cùng giả định, seed 0. Kết quả là con số mô phỏng
có giả định, KHÔNG phải kết quả đo. Dùng để chọn thiết kế mẫu (FINDINGS_LOG 2026-10-25), viết lần đầu bởi advisor.
"""

import json

import numpy as np
import pandas as pd

from address_misuse.config import FINAL_DIR, INTERIM_DIR


def main() -> None:
    ds=pd.read_parquet(FINAL_DIR / 'dataset_v2.parquet'); ev=pd.read_parquet(INTERIM_DIR / 'engine_eval.parquet')
    tau=json.load(open(INTERIM_DIR / 'engine_metrics.json', encoding='utf-8'))['main']['thresholds']['warn']
    ds['flag']=(ev.hard.notna().values)|(ev.R.values>=tau)
    pool=ds[((ds.split=='test')|ds.out_of_time)&(ds.split!='excluded')].reset_index(drop=True)
    pool['st']=np.where(pool.label_source=='d6_rule','+D6',pool.grp)
    pool['cell']=pool.st+np.where(pool.flag,'|F','|u')
    cells=pool.groupby('cell').size().to_dict(); print(cells)
    SC={'S1 vua':(dict(ADDR=.15,KEY=.30,NCD=.10,PCD=.40,D6=.20),dict(N1=.03,N2=.005,N3=.005,N4=.01,N5=.05,N6=0,N7=.02,N8=.01)),
        'S2 lac quan':(dict(ADDR=.05,KEY=.05,NCD=.05,PCD=.05,D6=.05),dict(N1=.002,N2=.002,N3=.002,N4=.002,N5=.002,N6=0,N7=.002,N8=.002))}
    A={'+ADDR':60,'+D6':42,'+KEY':60,'+NCD':80,'+PCD':50,'-N1':40,'-N2':60,'-N3':40,'-N4':30,'-N5':39,'-N6':5,'-N7':19,'-N8':80}
    def alloc_cells(per_st):
        # SRS trong tầng → chia theo cell tỉ lệ (kỳ vọng); làm tròn, ≥1 nếu cell có mẫu
        out={}
        for st,n in per_st.items():
            cs={c:N for c,N in cells.items() if c.split('|')[0]==st}; tot=sum(cs.values())
            for c,N in cs.items(): out[c]=min(N,max(1 if n>0 else 0,round(n*N/tot)))
        return out
    def census_pos(extra_neg):
        d={c:N for c,N in cells.items() if c[0]=='+' or c.endswith('|F')}
        for st in ['-N1','-N2','-N3','-N4','-N5','-N6','-N7','-N8']: d[st+'|u']=A[st]
        big=['-N1|u','-N2|u','-N3|u','-N4|u','-N8|u']; tot=sum(cells[c]-d[c] for c in big)
        for c in big: d[c]=min(cells[c],d[c]+round(extra_neg*(cells[c]-d[c])/tot))
        return d
    D={'A hien tai 605':alloc_cells(A),'B dieu tra het duong + 3 N8 co':census_pos(0),
       'C = B + 250 am':census_pos(250),'C2 = B + 500 am':census_pos(500),'E dieu tra toan bo':dict(cells)}
    d=census_pos(0); 
    for st in ['-N1','-N2','-N3','-N4','-N8']: d[st+'|u']=0
    rest=605-sum(d.values()); big=['-N1|u','-N2|u','-N3|u','-N4|u','-N8|u']; tot=sum(cells[c] for c in big)
    for c in big: d[c]=round(rest*cells[c]/tot)
    D['A2 605 phan bo lai']=d
    rng=np.random.default_rng(0)
    idx={c:np.flatnonzero(pool.cell.values==c) for c in cells}
    flag=pool.flag.values
    for sname,(q,r) in SC.items():
        print('\n==',sname)
        for dname,des in D.items():
            n=sum(des.values()); W={k:[] for k in ('P','R','FPR')}; bias={k:[] for k in W}
            for truth in range(10):
                y=np.zeros(len(pool),int)
                for c,ii in idx.items():
                    st=c.split('|')[0]; key=st[1:]
                    p=1-q[key] if st[0]=='+' else r[key]
                    y[ii]=rng.random(len(ii))<p
                tp=(flag&(y==1)).sum(); TP=dict(P=tp/flag.sum(),R=tp/y.sum(),FPR=(flag&(y==0)).sum()/(y==0).sum())
                est={k:[] for k in W}
                for rep in range(400):
                    a=b=cc=e=0.0
                    for c,m in des.items():
                        if m==0: continue
                        ii=idx[c]; s=ii if m>=len(ii) else rng.choice(ii,m,replace=False); w=len(ii)/len(s)
                        ys=y[s]; fs=flag[s]
                        a+=w*(fs&(ys==1)).sum(); b+=w*fs.sum(); cc+=w*(ys==1).sum(); e+=w*(fs&(ys==0)).sum()
                    negs=sum(len(idx[c]) for c in cells)-cc
                    est['P'].append(a/b); est['R'].append(a/cc); est['FPR'].append(e/negs)
                for k in W:
                    v=np.array(est[k]); W[k].append(np.quantile(v,.975)-np.quantile(v,.025)); bias[k].append(v.mean()-TP[k])
            print(f"{dname:32s} n={n:5d}  "+"  ".join(f"{k}: CI±{np.mean(W[k])/2*100:.2f}đ%" for k in W))


if __name__ == "__main__":
    main()
