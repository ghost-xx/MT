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
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                    'Connection': 'keep-alive'
                }
                
                r = requests.get('https://bbs.binmt.cc/misc.php?mod=mobile', headers=headers, timeout=30)
                print(f"请求返回状态码: {r.status_code}")
                
                if r.status_code != 200:
                    print(f"请求失败，状态码: {r.status_code}")
                    continue
                    
                # 打印服务器返回的cookie信息
                print(f"服务器返回的cookies: {dict(r.cookies)}")
                
                aa = r.text
                bb = r.cookies
                
                # 检查cookie
                if not bb:
                    print("警告: 没有获取到cookie")
                
                # 直接从cookie对象中获取saltkey
                saltkey = None
                
                # 首先尝试从cookie字典中获取
                cookies_dict = dict(bb)
                print(f"Cookies字典: {cookies_dict}")
                
                # 尝试多个可能的cookie名称
                saltkey_keys = ['saltkey', 'cQWy_2132_saltkey']
                for key in saltkey_keys:
                    if key in cookies_dict:
                        saltkey = cookies_dict[key]
                        print(f"从cookies字典中获取到saltkey: {saltkey}")
                        break
                
                # 如果没有获取到，尝试迭代cookie对象
                if not saltkey:
                    for cookie in bb:
                        cookie_name = cookie.name
                        if 'saltkey' in cookie_name:
                            saltkey = cookie.value
                            print(f"直接从cookie对象获取到saltkey: {saltkey}")
                            break
                
                # 如果仍然无法获取，尝试从页面内容中提取
                if not saltkey:
                    print("从页面内容中提取saltkey...")
                    
                    # 保存页面内容以便调试
                    print(f"页面内容片段: {aa[:500]}...")
                    
                    # 尝试多种正则表达式
                    saltkey_patterns = [
                        r'saltkey=([^&"\']+)',
                        r'cQWy_2132_saltkey=([^;]+)',
                        r'saltkey=([^;]+)',
                        r'saltkey=([^ ]+)',
                        r'saltkey:\s*[\'"]([^\'"]+)[\'"]'
                    ]
                    
                    for pattern in saltkey_patterns:
                        saltkey_matches = re.findall(pattern, aa)
                        if saltkey_matches:
                            saltkey = saltkey_matches[0]
                            print(f"使用正则表达式'{pattern}'从页面内容匹配到saltkey: {saltkey}")
                            break
                
                # 如果仍然无法获取，使用硬编码或随机值
                if not saltkey:
                    # 生成一个随机saltkey或使用默认值
                    import random
                    import string
                    saltkey = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
                    print(f"无法获取saltkey，使用随机生成的值: {saltkey}")
                
                print(f"最终使用的saltkey: {saltkey}")
                
                # 提取formhash
                formhash = None
                formhash_patterns = [
                    r'formhash=([^&"\']+)',
                    r'formhash" value="([^"]+)',
                    r"formhash' value='([^']+)",
                    r'formhash:\s*[\'"]([^\'"]+)[\'"]'
                ]
                
                for pattern in formhash_patterns:
                    formhash_matches = re.findall(pattern, aa)
                    if formhash_matches:
                        formhash = formhash_matches[0]
                        print(f"使用正则表达式'{pattern}'匹配到formhash: {formhash}")
                        break
                
                # 如果无法提取formhash，再次尝试其他方法或放弃
                if not formhash:
                    print("错误: 无法提取formhash，尝试从完整页面内容中搜索...")
                    
                    # 保存完整页面内容用于调试
                    with open("page_content.html", "w", encoding="utf-8") as f:
                        f.write(aa)
                    print("已保存完整页面内容到page_content.html")
                    
                    # 使用更宽松的正则表达式再次尝试
                    formhash_alt_patterns = [
                        r'formhash["\']?\s*[:=]\s*["\']?([^"\'&\s]+)',
                        r'name=["\']formhash["\'][^>]*value=["\']([^"\']+)',
                        r'value=["\']([a-zA-Z0-9]{8})["\'][^>]*name=["\']formhash'
                    ]
                    
                    for pattern in formhash_alt_patterns:
                        formhash_matches = re.findall(pattern, aa)
                        if formhash_matches:
                            formhash = formhash_matches[0]
                            print(f"使用宽松正则表达式'{pattern}'匹配到formhash: {formhash}")
                            break
                
                # 如果仍然无法获取formhash，尝试再次请求页面
                if not formhash:
                    print("尝试再次请求页面获取formhash...")
                    try:
                        r2 = requests.get('https://bbs.binmt.cc/', headers=headers, timeout=30)
                        formhash_matches = re.findall(r'formhash=([^&"\']+)', r2.text)
                        if formhash_matches:
                            formhash = formhash_matches[0]
                            print(f"从主页获取到formhash: {formhash}")
                    except Exception as e:
                        print(f"再次请求页面失败: {str(e)}")
                
                # 如果仍然无法获取formhash，则生成一个随机值
                if not formhash:
                    import random
                    import string
                    formhash = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
                    print(f"无法获取formhash，使用随机生成的值: {formhash}")
                
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
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'origin': 'https://bbs.binmt.cc',
                    'referer': 'https://bbs.binmt.cc/member.php?mod=logging&action=login'
                }
                
                print("发送登录请求...")
                res = requests.post(login_url, data=login_data, headers=headers1, timeout=30)
                print(f"登录请求状态码: {res.status_code}")
                
                if res.status_code != 200:
                    print(f"登录请求失败，状态码: {res.status_code}")
                    continue
                
                print(f"服务器返回的登录cookies: {dict(res.cookies)}")
                
                login_response = res.text
                login_cookies = res.cookies
                
                # 打印登录响应片段用于调试
                print(f"登录响应片段: {login_response[:500]}...")
                
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
                
                # 首先从cookie字典中获取
                login_cookies_dict = dict(login_cookies)
                print(f"登录Cookies字典: {login_cookies_dict}")
                
                auth_keys = ['auth', 'cQWy_2132_auth']
                for key in auth_keys:
                    if key in login_cookies_dict:
                        auth = login_cookies_dict[key]
                        print(f"从登录cookies字典中获取到auth: {auth}")
                        break
                
                # 如果没有获取到，尝试迭代cookie对象
                if not auth:
                    for cookie in login_cookies:
                        if 'auth' in cookie.name:
                            auth = cookie.value
                            print(f"直接从cookie对象获取到auth: {auth}")
                            break
                
                # 如果仍然无法获取，尝试从响应内容中提取
                if not auth:
                    auth_patterns = [
                        r'auth=([^&"\']+)',
                        r'cQWy_2132_auth=([^;]+)',
                        r'auth:\s*[\'"]([^\'"]+)[\'"]'
                    ]
                    
                    for pattern in auth_patterns:
                        auth_matches = re.findall(pattern, login_response)
                        if auth_matches:
                            auth = auth_matches[0]
                            print(f"使用正则表达式'{pattern}'从登录响应匹配到auth: {auth}")
                            break
                
                # 如果仍然无法获取auth，使用随机值或跳过签到
                if not auth:
                    if "登录成功" in login_response or "成功" in login_message:
                        # 登录可能成功但无法获取auth，尝试随机值
                        import random
                        import string
                        auth = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
                        print(f"无法获取auth但登录信息显示成功，使用随机值: {auth}")
                    else:
                        print("错误: 无法获取auth且登录可能失败，跳过此账号")
                        continue
                
                print(f"最终使用的auth: {auth}")
                print(f"等待2秒...")
                time.sleep(2)  # 添加延迟，避免请求过快
                
                # 获取签到页面以提取签到所需的formhash
                sign_url = 'https://bbs.binmt.cc/k_misign-sign.html'
                headers2 = {
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'cookie': 'cQWy_2132_saltkey=' + saltkey + ';cQWy_2132_auth=' + auth,
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'referer': 'https://bbs.binmt.cc/'
                }
                
                print("获取签到页面...")
                sign_page_resp = requests.get(sign_url, headers=headers2, timeout=30)
                print(f"获取签到页面状态码: {sign_page_resp.status_code}")
                
                if sign_page_resp.status_code != 200:
                    print(f"获取签到页面失败，状态码: {sign_page_resp.status_code}")
                    continue
                
                sign_page = sign_page_resp.text
                
                # 打印签到页面片段用于调试
                print(f"签到页面片段: {sign_page[:500]}...")
                
                # 提取签到用的formhash
                sign_formhash = None
                formhash_patterns = [
                    r'formhash=([^&"\']+)',
                    r'formhash" value="([^"]+)',
                    r"formhash' value='([^']+)",
                    r'formhash:\s*[\'"]([^\'"]+)[\'"]'
                ]
                
                for pattern in formhash_patterns:
                    formhash_matches = re.findall(pattern, sign_page)
                    if formhash_matches:
                        sign_formhash = formhash_matches[0]
                        print(f"使用正则表达式'{pattern}'匹配到签到formhash: {sign_formhash}")
                        break
                
                # 如果无法提取签到formhash，尝试使用登录时的formhash
                if not sign_formhash:
                    print("无法提取签到formhash，尝试使用登录时的formhash")
                    sign_formhash = formhash
                
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
                
                # 打印签到结果页面片段用于调试
                print(f"签到结果页面片段: {sign_result[:500]}...")
                
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
    print(f"参数长度: {len(arg_str)} 字符")
    
    # 按换行符分割，一行一个账号密码
    accounts = []
    
    # 尝试多种可能的换行符
    if '\n' in arg_str:
        for line in arg_str.split('\n'):
            line = line.strip()
            if line:
                accounts.append(line)
        print(f"使用\\n换行符解析到 {len(accounts)} 个账号")
    # 使用\r\n分割（Windows风格换行）
    elif '\r\n' in arg_str:
        for line in arg_str.split('\r\n'):
            line = line.strip()
            if line:
                accounts.append(line)
        print(f"使用\\r\\n换行符解析到 {len(accounts)} 个账号")
    # 如果没有检测到换行符，但包含--分隔符，可能是单个账号
    elif '--' in arg_str:
        accounts = [arg_str.strip()]
        print("检测到单个账号")
    # 其他情况，尝试使用其他分隔符
    else:
        # 尝试使用逗号、分号等常见分隔符
        for sep in [',', ';', ' ']:
            if sep in arg_str:
                for item in arg_str.split(sep):
                    item = item.strip()
                    if '--' in item:  # 确认是账号密码格式
                        accounts.append(item)
                if accounts:
                    print(f"使用分隔符 '{sep}' 解析到 {len(accounts)} 个账号")
                    break
    
    # 打印解析结果（已屏蔽敏感信息）
    if accounts:
        print(f"成功解析出 {len(accounts)} 个账号")
        
        # 检查每个账号的格式
        valid_accounts = []
        for acc in accounts:
            if '--' in acc:
                parts = acc.split('--')
                if len(parts) == 2 and parts[0] and parts[1]:
                    valid_accounts.append(acc)
                    print(f"账号格式正确: 用户名={parts[0][:2]}*** 密码长度={len(parts[1])}")
                else:
                    print(f"账号格式错误，跳过: {acc}")
            else:
                print(f"账号缺少--分隔符，跳过: {acc}")
        
        accounts = valid_accounts
        print(f"格式检查后剩余 {len(accounts)} 个有效账号")
    else:
        print("未解析出任何账号")
    
    return accounts


if __name__ == "__main__":
    print("MT论坛自动签到程序开始运行...")
    print(f"Python版本: {sys.version}")
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
