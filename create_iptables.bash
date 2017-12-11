#!/bin/bash
#Внешний интерфейс
export WAN=ens192
export WAN_IP=192.168.1.184
#Локальная сеть
export LAN=ens192
export LAN_IP=192.168.1.184
export MAILPORTS=25,110,143,456,587,993,995
export SQL=3306,5432
export SSH_PORT=22
export FILE=./iptables.conf
exec > $FILE
echo "#port			|	description"
echo "#$SSH_PORT		|	ssh"
echo "#20:21			|	ftp date"
echo "#35000:35999		|	pasive ftp"
echo "#25			|	SMTP"
echo "#80			|	HTTP"
echo "#443			|	HTTPS"
echo "#110			|	POP3"
echo "#143			|	IMAP"
echo "#465			|	URD"
echo "#587			|	SUBMISSION"
echo "#993			|	IMAPS"
echo "#995			|	POP3S"
echo "#53			|	DOMAIN"
echo "#3306			|	MySQL"
echo "#5432			|	PostgreSQL"
echo "#1500			|	ISPPanel"

#Create nat
echo "*nat
:INPUT ACCEPT [0:0]
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
#Включаем nat 
-A POSTROUTING -o $WAN -j SNAT --to-source $WAN_IP
COMMIT
"
#Create filter
echo "
#create chain
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:ssh_brute_check - [0:0]
:block_in - [0:0]
:block_out - [0:0]
:block_fw - [0:0]
"
#Разрешение любого трафика, входящего на локальный сервис
echo "
#Разрешение любого трафика, входящего на локальный сервис
-A INPUT -i lo -j ACCEPT
-A INPUT -i $LAN -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -o $LAN -j ACCEPT
"

#Разрешение делать ping
echo "
#Разрешение делать ping
-I INPUT -p icmp --icmp-type 8 -j ACCEPT
"
#Открыть доступ в интернет серверу
echo "
#Открыть доступ в интернет серверу
-A OUTPUT -o $WAN -j ACCEPT
-A OUTPUT -o $WAN -j ACCEPT
"
#Рарешаем все установленные разрешения и дочернии для от них.
echo "
#Рарешаем все установленные разрешения и дочернии для от них.
-A INPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
"


##Защита от сетевых атак
echo "
#Блокировать все попытки открыть входящее TCP-соединение не SYN-пакетом. Отражение атаки syn-flood 
-I INPUT -m conntrack --ctstate NEW -p tcp ! --syn -j DROP
-I FORWARD -m conntrack --ctstate NEW -p tcp ! --syn -j DROP

#Защита от спуфинга
-I INPUT -m addrtype --src-type LOCAL ! -i lo -j DROP

#блокирует фрагменты ICMP-пакетов.
-I INPUT -p icmp -f -j DROP

#Отбросить пакеты без статуса
-A INPUT -m state --state INVALID -j DROP
-A FORWARD -m state --state INVALID -j DROP

#Блокировка нулевых пакетов 
-A INPUT -p tcp --tcp-flags ALL NONE -j DROP

#Защита от разведовательных пакетов XMAS
-A INPUT -p tcp --tcp-flags ALL ALL -j DROP

#Разрешаем все выход в интернет
-A FORWARD -i $LAN -o $WAN -j ACCEPT

#Запрет доступа из инета в локальную сеть
-A FORWARD -i $WAN -o $LAN -j REJECT
"

##Разрешения
echo "
#Блокирование bruteforce-атак
# Если за последние 10 минут (600 секунд) с одного адреса было 5 или более новых соединений — блокируем этот адрес
-A ssh_brute_check -m conntrack --ctstate NEW -m recent --update --seconds 600 --hitcount 5 -j DROP
# В противном случае — разрешаем, и при этом заносим в список
-A ssh_brute_check -m recent --set -j ACCEPT
# Все попытки открыть новое соединение по SSH направляем на проверку
-A INPUT -i $WAN -m conntrack --ctstate NEW -p tcp -m multiport --dport $SSH_PORT -j ssh_brute_check
#Ограничение на число открытий новых соеденений в секунду
-A INPUT -i $WAN -p tcp -m multiport --dport 80,443,1500 -m conntrack --ctstate NEW -m limit --limit 32/sec --limit-burst 32 -j ACCEPT
-A INPUT -i $WAN -p tcp -m multiport --dport 21 -m conntrack --ctstate NEW -m limit --limit 32/sec --limit-burst 32 -j ACCEPT
#ftp в пассивном режиме
-A INPUT -i $WAN -p tcp -m conntrack --ctstate NEW -m multiport --dports 35000:35999 -j ACCEPT
"
#Правила по умолчанию
echo "
#Правила по умолчанию
-P INPUT DROP
-P OUTPUT ACCEPT
-P FORWARD DROP
"
#Логирование
echo '
#Включить логирование. Перенапрваить заблокированные пакеты в отдельные цепочки и маркировать в логах каждое их направление

-A INPUT -j block_in
-A OUTPUT -j block_out
-A FORWARD -j block_fw

#-A block_in -j LOG --log-level info --log-prefix "--IN--BLOCK"
-A block_in -j DROP
#-A block_out -j LOG --log-level info --log-prefix "--OUT--BLOCK"
-A block_out -j DROP
#-A block_fw -j LOG --log-level info --log-prefix "--FW--BLOCK"
-A block_fw -j DROP
'
echo "COMMIT"
echo "#Create: "`date`

