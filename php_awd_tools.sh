#!/bin/bash

webapp="/var/www/html"
target_folder="/tmp/backup.tar.gz"
waf_file="$webapp/RCEw4f.php"
monitor_file="$webapp/phpMonitor.php"

while true; do
    echo '  ____  _   _ ____       ___        ______    _____           _     '
    echo ' |  _ \| | | |  _ \     / \ \      / /  _ \  |_   _|__   ___ | |___ '
    echo ' | |_) | |_| | |_) |   / _ \ \ /\ / /| | | |   | |/ _ \ / _ \| / __|'
    echo ' |  __/|  _  |  __/   / ___ \ V  V / | |_| |   | | (_) | (_) | \__ \'
    echo ' |_|   |_| |_|_|     /_/   \_\_/\_/  |____/    |_|\___/ \___/|_|___/'
    echo '                                                                    '
    echo "Author: C1oudfL0w0"
    echo "1. 备份源码"
    echo "2. 查后门"
    echo "3. 添加waf"
    echo "4. 流量监控"
    echo "5. 检查进程与可写目录"
    echo "6. 移除waf"
    echo "7. 源码恢复"
    echo "q. 退出"

    read -p "请输入选项:" choice

    case $choice in
    1)
        echo "备份源码..."

        if [ -f "$target_folder" ]; then
            echo "源码备份已存在: $target_folder"
        else
            echo "执行压缩命令..."
            cd $webapp && tar -cvzf "$target_folder" .
        fi
        ;;
    2)
        echo "查后门..."
        # 排除项
        exclude_files=""
        exclude="*.js *.sh info.txt *.map *.so.* *.so *.tar *.zip *.md *.css RCEw4f.php LICENSE phpMonitor.php"

        exclude_dirs=""
        for dir in $exclude_files; do
            exclude_dirs="$exclude_dirs --exclude-dir=$dir"
        done

        exclude_files_arg=""
        for ext in $exclude; do
            exclude_files_arg="$exclude_files_arg --exclude=$ext"
        done

        {
            echo "------疑似预留eval后门------"
            grep -rnw '.' -e "eval" $exclude_dirs $exclude_files_arg
            echo "------疑似预留system后门------"
            grep -rnw '.' -e "system" $exclude_dirs $exclude_files_arg
            echo "------预留poc：------"
            grep -rnw '.' -e "\$poc" $exclude_dirs $exclude_files_arg
        } >/tmp/vuln.txt
        echo "查找后门完毕: 已输出至 /tmp/vuln.txt"
        echo
        ;;
    3)
        echo "加载waf..."
        waf="<?php
        \$wafpattern = \"/\b(?:call_user_func|call_user_func_array|array_map|array_filter|ob_start|phpinfo|eval|assert|passthru|pcntl_exec|exec|system|escapeshellcmd|popen|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|ob_start|echo|file_put_contents)\b/i\";

        foreach (\$_GET as \$param) {
            if (preg_match(\$wafpattern, \$param) == 1 || strpos(\$param, \"\`\") !== false) {
                die('flag{You shall die!}');
            }
        }

        foreach (\$_POST as \$param) {
            if (preg_match(\$wafpattern, \$param) == 1 || strpos(\$param, \"\`\") !== false) {
                die('flag{You shall die!}');
            }
        }
        ?>"

        if [ ! -f "$waf_file" ]; then
            echo "$waf" >"$waf_file"
            chmod 644 "$waf_file"
        fi

        find "$webapp" -type f -name "*.php" ! -path "$waf_file" ! -path "$monitor_file" | while read php_file; do
            if ! grep -q "include_once.*RCEw4f.php" "$php_file"; then
                sed -i "1a include_once('$waf_file');" "$php_file"
                echo "已添加 WAF 到: $php_file"
            else
                echo "已存在 WAF: $php_file"
            fi
        done
        ;;
    4)
        echo "启动监控..."
        Monitor="<?php
        \$ip = \$_SERVER[\"REMOTE_ADDR\"];
        \$filename = \$_SERVER['PHP_SELF'];
        \$parameter = \$_SERVER[\"QUERY_STRING\"];
        \$method = \$_SERVER['REQUEST_METHOD'];
        \$uri = \$_SERVER['REQUEST_URI'];
        \$time = date('Y-m-d H:i:s', time());
        \$post = file_get_contents(\"php://input\", 'r');
        \$others = '...其他你想得到的信息...';
        \$logadd = 'Visit Time：'.\$time.' '.'Visit IP：'.\$ip.\"\\r\\n\".'RequestURI：'.\$uri.' '.\$parameter.'RequestMethod：'.\$method.\"\\r\\n\";
        \$fh = fopen(\"/tmp/log.txt\", \"a+\");
        fwrite(\$fh, \$logadd);
        fwrite(\$fh, print_r(\$_COOKIE, true).\"\\r\\n\");
        fwrite(\$fh, \$post.\"\\r\\n\");
        fwrite(\$fh, \$others.\"\\r\\n\");
        fclose(\$fh);
        ?>"

        if [ ! -f $monitor_file ]; then
            echo "$Monitor" >"$monitor_file"
            chmod 644 "$monitor_file"
        fi

        find "$webapp" -type f -name "*.php" ! -path "$monitor_file" ! -path "$waf_file" | while read php_file; do
            if ! grep -q "include_once.*phpMonitor.php" "$php_file"; then
                sed -i "1a include_once('$monitor_file');" "$php_file"
                echo "已部署流量监控到: $php_file"
            else
                echo "已存在流量监控: $php_file"
            fi
        done
        ;;
    5)
        echo "进程信息："
        ps -aux #| grep 'www-data'
        echo

        echo "可写目录检查："
        find / -type d -perm -002 2>/dev/null
        echo
        ;;
    6)
        echo "正在移除 WAF..."

        if [ -f "$waf_file" ]; then
            rm -f "$waf_file"
            echo "已删除 WAF 文件: $waf_file"
        else
            echo "WAF 文件不存在: $waf_file"
        fi

        escaped_waf_path=$(echo "$waf_file" | sed 's/\//\\\//g')
        find "$webapp" -type f -name "*.php" | while read php_file; do
            if grep -q "include_once.*RCEw4f.php" "$php_file"; then
                # \(['\"]\)\?：匹配单引号、双引号或无引号
                # \(\.\/\)\?：匹配 ./ 或无路径前缀
                sed -i "/include_once('$escaped_waf_path');/d" "$php_file"
                echo "已清理: $php_file"
            fi
        done

        echo "WAF 移除完成"
        ;;
    7)
        echo "源码恢复..."
        tar -xvzf "$target_folder" -C "$webapp"
        echo "已恢复源码"
        ;;
    q)
        echo "byebye"
        break
        ;;
    *)
        echo "选项有误"
        ;;
    esac
done
