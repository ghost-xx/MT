import requests
import re
import sys


def sign_in(account_pwd_list):
    for i in account_pwd_list:
        # 开始登录
        try:
            # 检查账号密码格式
            if '--' not in i:
                print(f"跳过格式错误的账号密码: {i} (缺少'--'分隔符)")
                continue

            parts = i.split('--')
            if len(parts) != 2:
                print(f"跳过格式错误的账号密码: {i} (分隔后不是两部分)")
                continue

            user, pwd = parts

            print(f"正在处理用户: {user}")
            
            try:
                r = requests.get('https://bbs.binmt.cc/misc.php?mod=mobile', timeout=10)
                print(f"请求返回状态码: {r.status_code}")
                aa = r.text
                bb = r.cookies
                
                # 检查cookie
                if not bb:
                    print("警告: 没有获取到cookie")
                    
                # 查找saltkey (增加调试信息并优化正则)
                print("尝试获取saltkey...")
                cookies_str = str(bb)
                print(f"Cookies: {cookies_str}")
                
                # 更改正则表达式匹配方式
                saltkey = None
                for cookie in bb:
                    if 'saltkey' in cookie.name:
                        saltkey = cookie.value
                        break
                        
                if not saltkey:
                    # 尝试旧方法提取
                    test1 = r'saltkey=(.*?) for'
                    saltkey_matches = re.findall(test1, cookies_str)
                    if saltkey_matches:
                        saltkey = saltkey_matches[0]
                    else:
                        print("无法提取saltkey，尝试另一种方法...")
                        # 尝试更宽松的正则表达式
                        test1_alt = r'saltkey=([^;]+)'
                        saltkey_matches = re.findall(test1_alt, cookies_str)
                        if saltkey_matches:
                            saltkey = saltkey_matches[0]
                        else:
                            print("错误: 无法从响应中提取saltkey")
                            continue
                
                print(f"获取到saltkey: {saltkey}")
                
                # 提取formhash (添加更多调试信息和错误处理)
                rule = r'formhash=(.*?)&amp'
                formhash_matches = re.findall(rule, aa)
                if not formhash_matches:
                    print("错误: 无法提取formhash，尝试更宽松的正则表达式...")
                    # 尝试更宽松的正则表达式
                    rule_alt = r'formhash=([^&]+)'
                    formhash_matches = re.findall(rule_alt, aa)
                    if not formhash_matches:
                        print("错误: 使用宽松正则仍无法提取formhash，跳过此账号")
                        continue
                
                formhash = formhash_matches[0]
                print(f"获取到formhash: {formhash}")
                
                P1 = ('formhash=' + formhash + (
                    '&referer=https%3A%2F%2Fbbs.binmt.cc%2Fk_misign-sign.html&fastloginfield=username'
                    '&cookietime=31104000&username=') + user + '&password=' + pwd +
                  '&questionid=0&answer=&submit=true')
                headers1 = {
                    'cookie': 'cQWy_2132_saltkey=' + saltkey,
                    'content-type': 'application/x-www-form-urlencoded; charset=UTF-8'
                }
                
                print("正在发送登录请求...")
                res = requests.post(
                    'https://bbs.binmt.cc/member.php?mod=logging&action=login&loginsubmit=yes&loginhash=&handlekey=loginform'
                    '&inajax=1',
                    data=P1, headers=headers1, timeout=10)
                    
                print(f"登录请求状态码: {res.status_code}")
                cx = res.text
                cv = res.cookies
                
                # 提取登录结果
                testx = r"sign-sign.html', '(.*?)，现在将转入登录"
                logn_matches = re.findall(testx, cx)
                
                if not logn_matches:
                    print("警告: 无法从登录响应中提取登录结果")
                    print(f"登录响应: {cx[:200]}...")  # 打印部分响应用于调试
                    
                    # 尝试使用更宽松的正则表达式
                    testx_alt = r"'(.*?)，现在将转入"
                    logn_matches = re.findall(testx_alt, cx)
                    if not logn_matches:
                        print("错误: 无法确认登录结果，但将继续尝试")
                        logn = "未知登录结果"
                    else:
                        logn = logn_matches[0]
                else:
                    logn = logn_matches[0]
                
                print(f"用户 {user} 登录: {logn}")
                
                # 提取auth cookie
                test2 = r'cQWy_2132_auth=(.*?) for bbs.binmt.cc'
                auth_matches = re.findall(test2, str(cv))
                
                if not auth_matches:
                    print("警告: 无法提取auth cookie，尝试其他匹配方式...")
                    # 尝试更宽松的正则表达式
                    test2_alt = r'cQWy_2132_auth=([^;]+)'
                    auth_matches = re.findall(test2_alt, str(cv))
                    
                    if not auth_matches:
                        # 检查所有cookie
                        cQWy_2132_auth = None
                        for cookie in cv:
                            if 'auth' in cookie.name:
                                cQWy_2132_auth = cookie.value
                                break
                        
                        if not cQWy_2132_auth:
                            print("错误: 无法提取auth cookie，可能登录失败，跳过此账号")
                            continue
                    else:
                        cQWy_2132_auth = auth_matches[0]
                else:
                    cQWy_2132_auth = auth_matches[0]
                
                print(f"获取到auth: {cQWy_2132_auth}")

                # 获取Formhash
                headers2 = {
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                              'application/signed-exchange;v=b3;q=0.9',
                    'cookie': 'cQWy_2132_saltkey=' + saltkey + ';cQWy_2132_auth=' + cQWy_2132_auth
                }
                
                print("正在获取签到页面...")
                r1 = requests.get('https://bbs.binmt.cc/k_misign-sign.html', headers=headers2, timeout=10)
                print(f"获取签到页面状态码: {r1.status_code}")
                
                cc = r1.text
                rule11 = r'formhash=(.*?)&amp'
                formhash11_matches = re.findall(rule11, cc)
                
                if not formhash11_matches:
                    print("错误: 无法从签到页面提取formhash，尝试更宽松的正则表达式...")
                    # 尝试更宽松的正则表达式
                    rule11_alt = r'formhash=([^&]+)'
                    formhash11_matches = re.findall(rule11_alt, cc)
                    if not formhash11_matches:
                        print("错误: 无法提取签到formhash，跳过此账号")
                        continue
                        
                formhash11 = formhash11_matches[0]
                print(f"获取到签到formhash: {formhash11}")

                ##签到
                P3 = {
                    'operation': 'qiandao',
                    'formhash': formhash11,
                    'cookie': 'cQWy_2132_saltkey=' + saltkey + ';cQWy_2132_auth=' + cQWy_2132_auth
                }
                headers3 = {
                    'cookie': P3['cookie']
                }

                print("正在发送签到请求...")
                res = requests.get('https://bbs.binmt.cc/k_misign-sign.html', params=P3, headers=headers3, timeout=10)
                print(f"签到请求状态码: {res.status_code}")
                
                if res.status_code == 200:
                    r = res.text
                    z = r"(?<=CDATA).*?.\]"
                    m = re.search(z, r)
                    
                    if m:
                        print(f'用户 {user} 签到结果:', m[0])
                    else:
                        print(f"用户 {user} 签到结果: 无法提取签到结果，但请求成功")
                        # 检查是否有其他可能的结果指示
                        if "已签到" in r or "签到成功" in r:
                            print(f"用户 {user} 可能已成功签到")
                else:
                    print(f"用户 {user} 签到请求失败，状态码: {res.status_code}")
                    
            except requests.exceptions.RequestException as req_err:
                print(f"网络请求错误: {str(req_err)}")
                
        except Exception as e:
            print(f"处理过程中出错: {str(e)}")
            import traceback
            print("错误详情:")
            traceback.print_exc()


def parse_command_line():
    """解析命令行参数，返回账号密码列表"""
    # 检查参数数量
    if len(sys.argv) <= 1:
        return []
    
    # 获取命令行参数
    arg_str = ' '.join(sys.argv[1:])
    
    # 按换行符分割，一行一个账号密码（适合GitHub Actions环境变量）
    accounts = []
    for line in arg_str.split('\n'):
        line = line.strip()
        if line:
            accounts.append(line)
    
    return accounts


if __name__ == "__main__":
    account_pwd_list = parse_command_line()

    if account_pwd_list:
        print(f"解析出的账号密码列表: {account_pwd_list}")
        sign_in(account_pwd_list)
    else:
        print("请提供账号密码列表参数")
        print("用法示例:")
        print("python index.py \"账号1--密码1\n账号2--密码2\n账号3--密码3\"")
        print("在GitHub Actions中使用环境变量格式，每行一个账号密码")
