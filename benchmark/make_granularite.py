import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt, numpy as np, pathlib
signals=["IP exacte","/24","/16","ASN / org.","domaine / SNI"]
precision=[0.57,0.69,0.73,0.81,0.65]; recall=[1.00,0.70,0.51,0.54,1.00]; f1=[0.72,0.69,0.60,0.65,0.78]
x=np.arange(len(signals)); w=0.26
fig,ax=plt.subplots(figsize=(10,5.2))
cp,cr,cf="#2166AC","#F4A259","#4DAF4A"
b1=ax.bar(x-w,precision,w,label="Précision",color=cp,edgecolor="white")
b2=ax.bar(x,recall,w,label="Rappel",color=cr,edgecolor="white")
b3=ax.bar(x+w,f1,w,label="F-mesure",color=cf,edgecolor="white")
for bars in (b1,b2,b3):
    for r in bars:
        h=r.get_height(); ax.text(r.get_x()+r.get_width()/2,h+0.015,f"{h:.2f}",ha="center",va="bottom",fontsize=9,fontweight="bold")
ax.annotate("meilleure\nprécision",xy=(3-w,0.81),xytext=(3-w,0.94),ha="center",fontsize=9,color=cp,fontweight="bold",arrowprops=dict(arrowstyle="->",color=cp))
ax.annotate("meilleur\nrappel",xy=(4,1.00),xytext=(4,1.10),ha="center",fontsize=9,color=cr,fontweight="bold",arrowprops=dict(arrowstyle="->",color=cr))
ax.set_xticks(x); ax.set_xticklabels(signals,fontsize=11)
ax.set_ylabel("valeur de la métrique",fontsize=11); ax.set_ylim(0,1.22)
ax.legend(loc="upper center",ncol=3,frameon=True,fontsize=11); ax.grid(axis="y",alpha=0.3); ax.set_axisbelow(True)
for s in ("top","right"): ax.spines[s].set_visible(False)
plt.tight_layout()
out=pathlib.Path("benchmark/figures/granularite_signal.png")
plt.savefig(out,dpi=300,bbox_inches="tight"); print("OK 300dpi ->",out)
