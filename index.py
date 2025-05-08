import requests
import re
import sys
import time


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
            print(f"等待2秒...")
            time.sleep(2)  # 添加延迟，避免请求过快被服务器拒绝
            
            try:
                print(f"开始请求网站...")
                r = requests.get('https://bbs.binmt.cc/misc.php?mod=mobile', timeout=30)
                print(f"请求返回状态码: {r.status_code}")
                
                if r.status_code != 200:
                    print(f"请求失败，状态码: {r.status_code}")
                    continue
                    
                aa = r.text
                bb = r.cookies
                
                # 检查cookie
                if not bb:
                    print("警告: 没有获取到cookie")
                
                # 直接从cookie对象中获取saltkey
                saltkey = None
                for cookie in bb:
                    cookie_name = cookie.name
                    if 'saltkey' in cookie_name:
                        saltkey = cookie.value
                        print(f"直接从cookie对象获取到saltkey: {saltkey}")
                        break
                
                # 如果直接获取失败，尝试从字符串中提取
                if not saltkey:
                    print("从cookie字符串中提取saltkey...")
                    cookies_str = str(bb)
                    
                    # 如果是RequestsCookieJar，尝试以不同方式提取
                    if hasattr(bb, 'get_dict'):
                        cookie_dict = bb.get_dict()
                        print(f"Cookie字典: {cookie_dict}")
                        # 查找含有saltkey的键
                        for key in cookie_dict:
                            if 'saltkey' in key:
                                saltkey = cookie_dict[key]
                                print(f"从cookie字典获取到saltkey: {saltkey}")
                                break
                
                    # 尝试从cookie字符串中提取
                    if not saltkey:
                        # 尝试多种正则表达式
                        patterns = [
                            r'cQWy_2132_saltkey=([^;]+)',
                            r'saltkey=([^;]+)',
                            r'saltkey=([^ ]+)'
                        ]
                        
                        for pattern in patterns:
                            matches = re.findall(pattern, cookies_str)
                            if matches:
                                saltkey = matches[0]
                                print(f"使用正则表达式'{pattern}'匹配到saltkey: {saltkey}")
                                break
                
                # 如果仍然无法获取saltkey，尝试硬编码或从响应中查找
                if not saltkey:
                    print("所有方法都无法获取saltkey，尝试从页面内容中查找...")
                    # 尝试从页面内容中查找
                    saltkey_page_pattern = r'saltkey=([^&"\']+)'
                    saltkey_matches = re.findall(saltkey_page_pattern, aa)
                    if saltkey_matches:
                        saltkey = saltkey_matches[0]
                        print(f"从页面内容中获取到saltkey: {saltkey}")
                
                # 如果仍然无法获取saltkey，放弃处理此账号
                if not saltkey:
                    print("错误: 无法获取saltkey，跳过此账号")
                    continue
                    
                print(f"最终使用的saltkey: {saltkey}")
                
                # 提取formhash
                formhash = None
                formhash_patterns = [
                    r'formhash=([^&"\']+)',
                    r'formhash" value="([^"]+)',
                    r"formhash' value='([^']+)"
                ]
                
                for pattern in formhash_patterns:
                    formhash_matches = re.findall(pattern, aa)
                    if formhash_matches:
                        formhash = formhash_matches[0]
                        print(f"使用正则表达式'{pattern}'匹配到formhash: {formhash}")
                        break
                
                if not formhash:
                    print("错误: 无法提取formhash，跳过此账号")
                    continue
                
                print(f"最终使用的formhash: {formhash}")
                
                print(f"等待2秒...")
                time.sleep(2)  # 添加延迟，避免请求过快
                
                # 构建登录请求
                login_url = 'https://bbs.binmt.cc/member.php?mod=logging&action=login&loginsubmit=yes&loginhash=&handlekey=loginform&inajax=1'
                login_data = ('formhash=' + formhash + 
                    '&referer=https%3A%2F%2Fbbs.binmt.cc%2Fk_misign-sign.html' +
                    '&fastloginfield=username' +
                    '&cookietime=31104000' + 
                    '&username=' + user + 
                    '&password=' + pwd +
                    '&questionid=0&answer=&submit=true')
                    
                headers1 = {
                    'cookie': 'cQWy_2132_saltkey=' + saltkey,
                    'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                
                print("发送登录请求...")
                res = requests.post(login_url, data=login_data, headers=headers1, timeout=30)
                print(f"登录请求状态码: {res.status_code}")
                
                if res.status_code != 200:
                    print(f"登录请求失败，状态码: {res.status_code}")
                    continue
                
                login_response = res.text
                login_cookies = res.cookies
                
                # 提取登录结果
                login_message = "未知登录结果"
                login_patterns = [
                    r"'(.*?)，现在将转入",
                    r"'(登录成功.*?)'",
                    r'>(.*?)，现在将转入',
                    r'CDATA\[(.*?)，现在将'
                ]
                
                for pattern in login_patterns:
                    login_matches = re.findall(pattern, login_response)
                    if login_matches:
                        login_message = login_matches[0]
                        print(f"使用正则表达式'{pattern}'匹配到登录结果: {login_message}")
                        break
                
                print(f"用户 {user} 登录: {login_message}")
                
                # 无论是否提取到登录消息，都继续尝试获取auth cookie
                auth = None
                
                # 直接从cookie对象中获取auth
                for cookie in login_cookies:
                    if 'auth' in cookie.name:
                        auth = cookie.value
                        print(f"直接从cookie对象获取到auth: {auth}")
                        break
                
                # 如果直接获取失败，尝试从cookie字符串中提取
                if not auth:
                    login_cookies_str = str(login_cookies)
                    auth_patterns = [
                        r'cQWy_2132_auth=([^;]+)',
                        r'auth=([^;]+)',
                        r'auth=([^ ]+)'
                    ]
                    
                    for pattern in auth_patterns:
                        auth_matches = re.findall(pattern, login_cookies_str)
                        if auth_matches:
                            auth = auth_matches[0]
                            print(f"使用正则表达式'{pattern}'匹配到auth: {auth}")
                            break
                
                # 如果仍然无法获取auth，检查登录响应
                if not auth and "登录成功" in login_response:
                    print("登录可能成功但无法获取auth，尝试从登录页面获取...")
                    # 可能是特殊情况，尝试再次请求获取auth
                    # 此处可以添加额外的处理逻辑
                
                # 如果无法获取auth，放弃此账号
                if not auth:
                    print("错误: 无法获取auth，跳过此账号")
                    continue
                
                print(f"最终使用的auth: {auth}")
                print(f"等待2秒...")
                time.sleep(2)  # 添加延迟，避免请求过快
                
                # 获取签到页面以提取签到所需的formhash
                sign_url = 'https://bbs.binmt.cc/k_misign-sign.html'
                headers2 = {
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'cookie': 'cQWy_2132_saltkey=' + saltkey + ';cQWy_2132_auth=' + auth,
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                
                print("获取签到页面...")
                sign_page_resp = requests.get(sign_url, headers=headers2, timeout=30)
                print(f"获取签到页面状态码: {sign_page_resp.status_code}")
                
                if sign_page_resp.status_code != 200:
                    print(f"获取签到页面失败，状态码: {sign_page_resp.status_code}")
                    continue
                
                sign_page = sign_page_resp.text
                
                # 提取签到用的formhash
                sign_formhash = None
                formhash_patterns = [
                    r'formhash=([^&"\']+)',
                    r'formhash" value="([^"]+)',
                    r"formhash' value='([^']+)"
                ]
                
                for pattern in formhash_patterns:
                    formhash_matches = re.findall(pattern, sign_page)
                    if formhash_matches:
                        sign_formhash = formhash_matches[0]
                        print(f"使用正则表达式'{pattern}'匹配到签到formhash: {sign_formhash}")
                        break
                
                if not sign_formhash:
                    print("错误: 无法提取签到formhash，跳过此账号")
                    continue
                
                print(f"最终使用的签到formhash: {sign_formhash}")
                print(f"等待2秒...")
                time.sleep(2)  # 添加延迟，避免请求过快
                
                # 执行签到
                sign_params = {
                    'operation': 'qiandao',
                    'formhash': sign_formhash
                }
                sign_headers = {
                    'cookie': 'cQWy_2132_saltkey=' + saltkey + ';cQWy_2132_auth=' + auth,
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'referer': sign_url
                }
                
                print("发送签到请求...")
                sign_resp = requests.get(sign_url, params=sign_params, headers=sign_headers, timeout=30)
                print(f"签到请求状态码: {sign_resp.status_code}")
                
                if sign_resp.status_code != 200:
                    print(f"签到请求失败，状态码: {sign_resp.status_code}")
                    continue
                
                sign_result = sign_resp.text
                
                # 提取签到结果
                success_patterns = [
                    r"(?<=CDATA).*?.\]",
                    r"CDATA\[(.*?)\]",
                    r"签到成功[^<]*",
                    r"已签到[^<]*"
                ]
                
                sign_message = None
                for pattern in success_patterns:
                    sign_matches = re.search(pattern, sign_result)
                    if sign_matches:
                        sign_message = sign_matches.group(0)
                        print(f"使用正则表达式'{pattern}'匹配到签到结果: {sign_message}")
                        break
                
                if sign_message:
                    print(f'用户 {user} 签到结果: {sign_message}')
                else:
                    print(f"用户 {user} 签到结果: 无法提取具体结果，但请求已成功发送")
                    
                    # 检查是否有成功的关键词
                    if "已签到" in sign_result or "签到成功" in sign_result:
                        print(f"用户 {user} 可能已成功签到（检测到关键词）")
                
            except requests.exceptions.RequestException as req_err:
                print(f"网络请求错误: {str(req_err)}")
                
        except Exception as e:
            print(f"处理用户 {user} 过程中出错: {str(e)}")
            import traceback
            print("错误详情:")
            traceback.print_exc()
        
        print(f"完成处理用户: {user}")
        print("-" * 50)


def parse_command_line():
    """解析命令行参数，返回账号密码列表"""
    # 检查参数数量
    if len(sys.argv) <= 1:
        return []
    
    # 获取命令行参数（屏蔽实际内容，避免泄露敏感信息）
    print("解析命令行参数...")
    arg_str = ' '.join(sys.argv[1:])
    
    # 按换行符分割，一行一个账号密码（适合GitHub Actions环境变量）
    accounts = []
    for line in arg_str.split('\n'):
        line = line.strip()
        if line:
            accounts.append(line)
    
    # 打印解析结果（已屏蔽敏感信息）
    if accounts:
        print(f"成功解析出 {len(accounts)} 个账号")
    else:
        print("未解析出任何账号")
    
    return accounts


if __name__ == "__main__":
    print("MT论坛自动签到程序开始运行...")
    print("=" * 50)
    
    account_pwd_list = parse_command_line()
    
    if account_pwd_list:
        sign_in(account_pwd_list)
        print("所有账号处理完成！")
    else:
        print("请提供账号密码列表参数")
        print("用法示例:")
        print("python index.py \"账号1--密码1\n账号2--密码2\n账号3--密码3\"")
        print("在GitHub Actions中使用环境变量格式，每行一个账号密码")
    
    print("=" * 50)
    print("MT论坛自动签到程序执行结束")
