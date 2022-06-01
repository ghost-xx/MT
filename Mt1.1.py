import requests
import re


##账号格式
##    '账号--密码',
##加在第一排
账号密码 = {
    'wen55--xx123',
    'wen44--xx123'
}





for i in 账号密码:
    #开始登录
    user, pwd = i.split('--')
    r = requests.get('https://bbs.binmt.cc/misc.php?mod=mobile', timeout = 5)
    aa = r.text
    bb = r.cookies
    test1 = r'saltkey=(.*?) for'
    saltkey = re.findall(test1, str(bb))[0]
    rule = r'formhash=(.*?)&amp'
    formhash = re.findall(rule, aa)[0]   
    P1 = 'formhash='+formhash+'&referer=https%3A%2F%2Fbbs.binmt.cc%2Fk_misign-sign.html&fastloginfield=username&cookietime=31104000&username='+user+'&password='+pwd+'&questionid=0&answer=&submit=true'
    headers1 = {
    'cookie': 'cQWy_2132_saltkey=' + saltkey,
    'content-type': 'application/x-www-form-urlencoded; charset=UTF-8'
}
    res = requests.post('https://bbs.binmt.cc/member.php?mod=logging&action=login&loginsubmit=yes&loginhash=&handlekey=loginform&inajax=1', data = P1, headers = headers1, timeout = 5);
    cx=res.text
    cv=res.cookies
    testx = r"sign-sign.html', '(.*?)，现在将转入登录"
    test2 = r'cQWy_2132_auth=(.*?) for bbs.binmt.cc'
    cQWy_2132_auth=re.findall(test2, str(cv))[0]
    logn=re.findall(testx, str(cx))[0]
    print(logn)
    
    
    # 获取Formhash
    headers2 = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'cookie': 'cQWy_2132_saltkey=' + saltkey + ';cQWy_2132_auth=' + cQWy_2132_auth
}
    r1 = requests.get('https://bbs.binmt.cc/k_misign-sign.html', headers = headers2, timeout = 5)
    cc = r1.text
    rule11 = r'formhash=(.*?)&amp'
    formhash11 = re.findall(rule11, cc)[0]


    ##签到
    P3 = {
    'operation': 'qiandao',
    'formhash': formhash11,
    'cookie': 'cQWy_2132_saltkey='+saltkey+';cQWy_2132_auth='+ cQWy_2132_auth
}
    headers3 = {
    'cookie': P3['cookie']
}

    res = requests.get('https://bbs.binmt.cc/k_misign-sign.html', params=P3, headers=headers3, timeout=5);
    if res.status_code == 200:
            r = res.text
            z = r"(?<=CDATA).*?.\]"
            m = re.search(z, r)
            print('签到接口返回:', m[0])


