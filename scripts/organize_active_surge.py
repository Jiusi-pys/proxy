#!/usr/bin/env python3
"""Extract service lists while preserving the exact flattened Surge rule order."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
CLI='/Applications/Surge.app/Contents/Applications/surge-cli'
SECTION=re.compile(r'(?ms)^\[Rule\]\n(.*?)(?=^\[|\Z)')


def service(line):
    kind,value,policy,*options=line.split(',')
    if kind in ('FINAL','GEOIP','RULE-SET'):return None
    if kind=='PROTOCOL':return 'telegram-protocol'
    if kind=='PROCESS-NAME':
        if 'UURemote' in value:return 'uu-remote'
        if 'remoting_me2me' in value:return 'chrome-remote-desktop'
        return 'ai-applications'
    if value in ('cloudflare-dns.com','1.1.1.1/32','223.5.5.5/32','223.6.6.6/32','dns.alidns.com','dns.google','dns.quad9.net','dns.adguard.com'):
        return 'dns-'+('domestic' if policy=='DIRECT' else 'overseas')
    if kind in ('IP-CIDR','IP-CIDR6') or value in ('localhost','local'):return 'local-network'
    groups={
      'uu-remote':['nrd.nie.163.com','proxima.nie.netease.com','shence-api.mumu.163.com'],
      'tailscale':['controlplane.tailscale.com','login.tailscale.com','tailscale.com'],
      'gemini':['gemini.google.com','aistudio.google.com','generativelanguage.googleapis.com','ai.google.dev','makersuite.google.com','aiplatform.googleapis.com','vertexai.googleapis.com','*-aiplatform.googleapis.com'],
      'qwen-international':['dashscope-intl.aliyuncs.com'],
      'openai':['openai.com','chatgpt.com','oaistatic.com','oaiusercontent.com'],
      'anthropic':['anthropic.com','claude.ai'],
      'qwen-domestic':['dashscope.aliyun.com','dashscope.aliyuncs.com','qianwen.com','tongyi.com','tongyi.aliyun.com','cn-beijing.maas.aliyuncs.com'],
      'kimi':['kimi.com','kimi.ai','moonshot.cn'], 'doubao':['doubao.com','zijieapi.com'],
      'glm':['chatglm.cn','zhipuai.cn','bigmodel.cn'],'minimax':['minimaxi.com','minimax.chat'],
      'tencent':['qq.com','wechat.com','weixin.com','servicewechat.com','qpic.cn','qlogo.cn','tenpay.com'],
      'feishu':['feishu.cn','feishu.com','feishu.net','feishucdn.com'],
      'bilibili':['bilibili.com','biliapi.com','biliapi.net','bilivideo.com','hdslb.com'],
      'iqiyi':['iqiyi.com','iqiyipic.com'],'youku':['youku.com'],
      'alibaba-commerce':['taobao.com','tmall.com','alipay.com'],'jd':['jd.com','360buyimg.com'],
      'pinduoduo':['pinduoduo.com','yangkeduo.com'],'goofish':['goofish.com'],
      'baidu':['baidu.com','baidupcs.com'],'quark':['quark.cn','myquark.cn'],
      'weread':['weread.qq.com'],'ireader':['ireader.com','zhangyue.com'],
      'government-services':['gd.gov.cn','hdhwqx.cn'],'lark':['larksuite.com','larkoffice.com'],
      'apple-media':['news.apple.com','news-edge.apple.com','news-content.apple.com','tv.apple.com','apple.news'],
      'apple':['apple.com','icloud.com','icloud-content.com','apple-cloudkit.com','mzstatic.com','cdn-apple.com','apple-dns.net'],
      'netflix':['netflix.com','netflix.net','nflxvideo.net','nflximg.net','nflxso.net','nflxext.com'],
      'playstation':['playstation.com','playstation.net','sonyentertainmentnetwork.com'],
      'steam':['steampowered.com','steamcommunity.com','steamstatic.com','steamcontent.com','steamserver.net'],
      'google':['google.com','googleapis.com','googleusercontent.com','gstatic.com','gvt1.com','gvt2.com'],
      'youtube':['youtube.com','youtube-nocookie.com','youtu.be','ytimg.com','googlevideo.com'],
      'github':['github.com','githubusercontent.com','githubassets.com'],
      'huggingface':['huggingface.co','hf.co'],'ollama':['ollama.com','ollama.ai'],
      'notion':['notion.so','notion.com','notion.site','notionusercontent.com','notion-static.com'],
      'discord':['discord.com','discord.gg','discordapp.com','discordapp.net','discord.media'],
      'telegram':['telegram.org','t.me'],'whatsapp':['whatsapp.com','whatsapp.net'],
      'onedrive':['onedrive.com','1drv.com','onedrive.live.com','sharepoint.com'],
      'pikpak':['mypikpak.com'],'surge':['nssurge.com'],'cloudflare-reporting':['a.nel.cloudflare.com'],
      'china-tld':['cn'],'wps':['docer.com','ksord.com'],
    }
    found=[k for k,v in groups.items() if value in v]
    if len(found)!=1:raise ValueError('Unclassified rule: '+line)
    return found[0]


def rules(text):
    return [l.strip() for l in SECTION.search(text).group(1).splitlines() if l.strip() and not l.lstrip().startswith(('#',';','//'))]


def build(text,relative_dir):
    original=rules(text);blocks=[]
    for line in original:
        if line.startswith(('FINAL,','GEOIP,','RULE-SET,')):
            blocks.append((None,None,[],[line]));continue
        parts=line.split(',');key=service(line);policy=parts[2];options=parts[3:]
        # Separate every policy/option boundary to avoid set-wide option side effects.
        signature=(key,policy,options)
        if blocks and blocks[-1][:3]==signature:blocks[-1][3].append(line)
        else:blocks.append((key,policy,options,[line]))
    counts=Counter();files={};entries=[];new=[];expanded=[]
    for key,policy,options,lines in blocks:
        if key is None:new+=lines;expanded+=lines;continue
        counts[key]+=1
        name=key+(f'-part{counts[key]:02}' if counts[key]>1 else '')+'.list'
        # Move options to the reference: all members in this contiguous block share them.
        content=[','.join(line.split(',')[:2]) for line in lines]
        files[name]='# Service: '+key+'\n# Policy/options and ordering are defined by the parent profile.\n'+'\n'.join(content)+'\n'
        reference=','.join(['RULE-SET',relative_dir+'/'+name,policy]+options)
        new.append(reference)
        reconstructed=[','.join(rule.split(',')+[policy]+options) for rule in content]
        expanded+=reconstructed
        entries.append({'service':key,'file':name,'policy':policy,'options':options,'count':len(lines)})
    assert expanded==original,'Flattening changed rule order or options'
    replacement='[Rule]\n'+'\n'.join(new)+'\n\n'
    result=SECTION.sub(lambda _:replacement,text,count=1)
    assert SECTION.sub('[Rule]\n',result)==SECTION.sub('[Rule]\n',text),'Other sections changed'
    return result,files,{'original_rules':len(original),'organized_rules':len(new),'services':len(counts),'lists':entries,'flattened_exact_match':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('profile',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--list-directory',default='macbook-service-rules')
    args=parser.parse_args()
    text=args.profile.read_text()
    organized,files,report=build(text,args.list_directory)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    folder=args.output.parent/args.list_directory;folder.mkdir(exist_ok=True)
    for name,content in files.items():(folder/name).write_text(content)
    args.output.write_text(organized);args.output.chmod(0o600)
    (args.output.parent/'organization.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='lists'},ensure_ascii=False))

if __name__=='__main__':main()
