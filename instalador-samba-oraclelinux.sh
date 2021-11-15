#!/bin/bash

# inserido quotatool e winbind



# _____          _        _           _                  _       ______                _       _      
#|_   _|        | |      | |         | |                | |      |  _  \              (_)     (_)      
#  | | _ __  ___| |_ __ _| | __ _  __| | ___  _ __    __| | ___  | | | |___  _ __ ___  _ _ __  _  ___   
#  | || '_ \/ __| __/ _` | |/ _` |/ _` |/ _ \| '__|  / _` |/ _ \ | | | / _ \| '_ ` _ \| | '_ \| |/ _ \  
# _| || | | \__ \ || (_| | | (_| | (_| | (_) | |    | (_| |  __/ | |/ / (_) | | | | | | | | | | | (_) | 
# \___/_| |_|___/\__\__,_|_|\__,_|\__,_|\___/|_|     \__,_|\___| |___/ \___/|_| |_| |_|_|_| |_|_|\___/  
#


                       
DIR=`pwd`
NOME=`basename $0`
NOME_SCRIPT="$DIR/$NOME"



if [[ $EUID -ne 0 ]]; then

	whiptail --title "ERRO" --msgbox "Este script deve ser executado como root. Cancelando a instalação. Clique em OK para continuar." 8 78
	exit 1
fi

whiptail --title "Instalador-SAMBA" --msgbox "Script de instalação do SAMBA 4 versão 1.2.6 Clique em OK para continuar." 8 78


#------------------------------------------------------------------------------------------------------------------------
# Coleção de FUNÇÕES
#------------------------------------------------------------------------------------------------------------------------

validNetMask() 
{
   if echo $1 | grep -w -E -o '^(254|252|248|240|224|192|128)\.0\.0\.0|255\.(254|252|248|240|224|192|128|0)\.0\.0|255\.255\.(254|252|248|240|224|192|128|0)\.0|255\.255\.255\.(254|252|248|240|224|192|128|0)' > /dev/null; then
 #     echo "Valid netmask"
	  return 0
   else
      echo "Máscara inválida"
	  return 1
   fi
}

mask2cdr ()
{
   # Assumes there's no "255." after a non-255 byte in the mask
   local x=${1##*255.}
   set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) ${x%%.*}
   x=${1%%$3*}
   return $(( $2 + (${#x}/4) ))
}


cdr2mask ()
{
   # Number of args to shift, 255..255, first non-255 byte, zeroes
   set -- $(( 5 - ($1 / 8) )) 255 255 255 255 $(( (255 << (8 - ($1 % 8))) & 255 )) 0 0 0
   [ $1 -gt 1 ] && shift $1 || shift
   echo ${1-0}.${2-0}.${3-0}.${4-0}
}

get_netaddr ()
{
	Ip_Addr=$1
	Net_Mask=$2
	IFS=. 
	read -r io1 io2 io3 io4 <<< "$Ip_Addr"
	read -r mo1 mo2 mo3 mo4 <<< "$Net_Mask"
	IFS=	
	Net_Addr="$((io1 & mo1)).$(($io2 & mo2)).$((io3 & mo3)).$((io4 & mo4))"
	echo "$Net_Addr"
}

ler_parametro ()
{
# $Realm $Domain $Password $Naddr $Mcdr $End_dns 
    read x1 x2 x3 x4 x5 x6 < parametros.txt
    Realm=$x1
    Domain=$x2
    Password=$x3
    Naddr=$x4
    Mcdr=$x5
    End_dns=$x6
}

limpa_ambiente ()
{
    rm /root/rebooting-for-updates -f
    sed -i '/instala-samba/d ' /root/.bashrc
    rm /root/parametros.txt -f
}


#========================================================================================================================
# Início antes do reboot
#========================================================================================================================

antes_reboot ()
{

# Entrada de dados

 

#------------------------------------------------------------------------------------------------------------------------
#AD DC Hostname: serverfs
# variável: Hostname

while [ true ]
do
	Hostname=$(whiptail --title "AD DC Hostname" --inputbox "Nome do Servidor (Sigla da Empresa seguida de fs)" 10 60  3>&1 1>&2 2>&3)
	exitstatus=$?
	if [ $exitstatus = 1 ]; then
		echo "Cancelado."
		exit
	fi
	Hostname=$(echo "$Hostname" | sed 's/ //g')
	Hostname=$(echo $Hostname | tr '[:upper:]' '[:lower:]')
	if [ "${#Hostname}" -ge 5 ]; then 
		if (whiptail --title "Confirmação do Hostname" --yesno "Nome do Servidor: "$Hostname 8 78) then
    		break	
		fi
	else
		whiptail --title "ERRO" --msgbox "Nome de Host inválido. Clique em OK para continuar." 8 78
	fi

done 


#------------------------------------------------------------------------------------------------------------------------
#Realm: domain.ad
#AD DNS Domain Name: domain
#Fully Qualified Domain Name (FQDN): serverfs.domain.ad
# variável: Domain Realm FQDN

while [ true ]
do
	Domain=$(whiptail --title "AD Domain" --inputbox "Nome do Domínio (Máximo - 10 caracteres)" 10 60  3>&1 1>&2 2>&3)
	exitstatus=$?
	if [ $exitstatus = 1 ]; then
		echo "Cancelado."
		exit
	fi
	Domain=$(echo "$Domain" | sed 's/ //g')

	Domain=$(echo $Domain | tr '[:upper:]' '[:lower:]')
	if [ "${#Domain}" -eq  10 ]; then 
		if (whiptail --title "Confirmação do Nome de Domínio" --yesno "Nome de Domínio: "$Domain 8 78) then
    		break	
		fi
	else
		whiptail --title "ERRO" --msgbox "Nome de Domínio inválido. Clique em OK para continuar." 8 78
	fi
done 

Realm=$Domain".ad"
FQDN=$Hostname"."$Realm


#------------------------------------------------------------------------------------------------------------------------
#Server Role: Domain Controller (DC)
#Backend DNS: BIND9 DLZ
# variável: Server_Role Backend_DNS

Server_Role=dc
Backend_DNS=BIND9_DLZ



#------------------------------------------------------------------------------------------------------------------------
#Senha do Domain Admin: @#$#$%11sd!@!@#sdas (Não reutilize esta senha!)
# variável: Password

while [ true ]
do
	Password=$(whiptail --passwordbox "Senha do Administrator" 8 60 --title "Senha do Domain Administrator" 3>&1 1>&2 2>&3)

	if echo "$Password" | egrep "^.{8,255}"| egrep "[ABCDEFGHIJKLMNOPQRSTUVWXYZ]"| egrep "[abcdefghijklmnopqrstuvwxyz]" | egrep "[0-9]" >>/dev/null; then
    	
#		echo "forte"
		break
	else
		whiptail --title "ERRO" --msgbox "Senha fraca para Domain Administrator. Clique em OK para continuar." 8 70
	fi
done

exitstatus=$?

if [ $exitstatus != 0 ]; then
    echo "Cancelado"
    exit
fi



#------------------------------------------------------------------------------------------------------------------------
#Endereço IP do DC, máscara, CIDR, endereço de rede, gateway
# variável: End_IP Net_mask Mcdr Naddr


#endereço IP

while [ true ]
do
	End_IP=$(whiptail --title "Endereço IP do Controlador de Dominio" --inputbox "Endereço IP do Servidor SAMBA" 10 60  3>&1 1>&2 2>&3)
	exitstatus=$?
	if [ $exitstatus = 1 ]; then
		echo "Cancelado."
		exit
	fi
	End_IP=$(echo "$End_IP" | sed 's/ //g')
	exitstatus=$?
# Testa IP privado

	if expr "$End_IP" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; then
  		for i in 1 2 3 4; do
    		if [ $(echo "$End_IP" | cut -d. -f$i) -gt 255 ]; then
				whiptail --title "ERRO" --msgbox "Endereço IP inválido. Clique em OK para continuar." 8 78
				continue
    		fi
  		done
  		if echo $End_IP | grep -E '^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)' >/dev/null; then
      		if (whiptail --title "Confirmação IP do Controlador de Dominio" --yesno "Confirma Endereço IP ? "$End_IP 8 78) then
				break
			fi
		else
			whiptail --title "ERRO" --msgbox "Endereço IP inválido. Clique em OK para continuar." 8 78
		fi
	else
		whiptail --title "ERRO" --msgbox "Endereço IP inválido. Clique em OK para continuar." 8 78
		continue
	fi
done          
exitstatus=$?
if [ $exitstatus != 0 ]; then

    echo "Cancelado."
	exit
fi


#Net_mask

while [ true ]
do
	Net_mask=$(whiptail --title "Máscara de Rede" --inputbox "Máscara da Rede: (Formato xx.xx.xx.xx) " 10 60  3>&1 1>&2 2>&3)
	exitstatus=$?
	if [ $exitstatus = 1 ]; then
		echo "Cancelado."
		exit
	fi
	Net_mask=$(echo "$Net_mask" | sed 's/ //g')

	# Testa máscara
	validNetMask $Net_mask
	valido=$?
	if [ $valido = 0 ]; then
		if (whiptail --title "Confirmação da Máscara de Rede" --yesno "Confirma Máscara da Rede? "$Net_mask 8 78) then
				break
		fi
	else
		whiptail --title "ERRO" --msgbox "Máscara de Rede inválida. Clique em OK para continuar." 8 78
		continue
	fi
done  

exitstatus=$?
if [ $exitstatus = 0 ]; then
	mask2cdr $Net_mask
	Mcdr=$?
	Naddr=$( get_netaddr $End_IP $Net_mask )
else
    exit
fi




#------------------------------------------------------------------------------------------------------------------------
#Forwarder DNS Server: xxx.xxx.xxx.xxx
# variável $End_dns


while [ true ]
do
	End_dns=$(whiptail --title "Endereço IP do DNS Distrital" --inputbox "Endereço DNS Distrital" 10 60  3>&1 1>&2 2>&3)
	exitstatus=$?
	if [ $exitstatus = 1 ]; then
		echo "Cancelado."
		exit
	fi
	End_dns=$(echo "$End_dns" | sed 's/ //g')

#testa erro de digitação
if [ "$End_dns" == "$End_IP" ]; then
	whiptail --title "ERRO" --msgbox "Endereço de DNS inválido. Clique em OK para continuar." 8 78
	continue
fi


# Testa IP privado

	if expr "$End_dns" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; then
  		for i in 1 2 3 4; do
    		if [ $(echo "$End_dns" | cut -d. -f$i) -gt 255 ]; then
				whiptail --title "ERRO" --msgbox "Endereço de DNS inválido. Clique em OK para continuar." 8 78
				continue
    		fi
  		done
  		if echo $End_dns | grep -E '^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)' >/dev/null; then
      		        if (whiptail --title "Confirmação IP do DNS" --yesno "Confirma Endereço DNS? "$End_dns 8 78) then
				break
			fi
		else
			whiptail --title "ERRO" --msgbox "Endereço de DNS inválido. Clique em OK para continuar." 8 78			
		fi
	else
		continue
	fi
done          
exitstatus=$?
 if [ $exitstatus != 0 ]; then
    echo "Cancelado."
    exit
fi


#------------------------------------------------------------------------------------------------------------------------
# Servidor de NTP 200.160.7.193
# variável $End_ntp



while [ true ]
do
	End_ntp=$(whiptail --title "Servidor de Hora" --inputbox "Servidor de Hora: " 10 60  3>&1 1>&2 2>&3)
	exitstatus=$?
	if [ $exitstatus = 1 ]; then
                echo "Cancelado."
		exit
	fi

        End_ntp=$(echo "$End_ntp" | sed 's/ //g')
	

	if (whiptail --title "Confirmação do NTP" --yesno "Confirma Servidor de Hora? "$End_ntp 8 78) then
            break
	fi

done  

exitstatus=$?

if [ $exitstatus != 0 ]; then
    echo "Cancelado."
    exit
fi



#------------------------------------------------------------------------------------------------------------------------
# Configuração do Ambiente /etc/sysconfig/network-scripts/ifcfg-xxx
# variáveis $Placa

Placa=$( ip -o link show | awk '{print $2,$9}' | grep UP | cut -f 1 -d \: | head -n1 )
ip addr add $End_IP/$Mcdr dev $Placa
exitstatus=$?

if [ $exitstatus = 0 ]; then
	echo "Interface OK - " $Placa
else
	ip addr show dev  $Placa | grep 'inet '
	exitstatus=$?
	if [ $exitstatus != 0 ]; then
		whiptail --title "ERRO" --msgbox "OOPS algo deu errado. Abortando Instalação. Clique em OK para sair. COD:devdown" 8 78
		exit
	fi
fi

# VRF se está configurado
# trocar BOOTPROTO=dhcp por BOOTPROTO=none
# acrescentar:
#	IPADDR=$End_IP
#	PREFIX=$Mcdr
#	GATEWAY=$End_gw
#	DNS1=$End_IP
#	DNS2=$End_dns

# Read Gateway
while [ true ]
do
	End_gw=$(whiptail --title "Endereço IP do Gateway" --inputbox "Endereço gateway" 10 60  3>&1 1>&2 2>&3)
	exitstatus=$?
	if [ $exitstatus = 1 ]; then
		echo "Cancelado."
		exit
	fi
	# retirando espaços em branco
	End_gw=$(echo "$End_gw" | sed 's/ //g')

#testa erro de digitação
if [ "$End_gw" == "$End_IP" ]; then
	whiptail --title "ERRO" --msgbox "Endereço de gateway inválido. Clique em OK para continuar." 8 78
	continue
fi


# Testa IP privado

	if expr "$End_gw" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; then
  		for i in 1 2 3 4; do
    		if [ $(echo "$End_gw" | cut -d. -f$i) -gt 255 ]; then
				whiptail --title "ERRO" --msgbox "Endereço de gateway inválido. Clique em OK para continuar." 8 78
				continue
    		fi
  		done
  		if echo $End_dns | grep -E '^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)' >/dev/null; then
      		if (whiptail --title "Confirmação IP do gateway" --yesno "Confirma Endereço do gateway ? "$End_gw 8 78) then
				break
			fi
		else
			whiptail --title "ERRO" --msgbox "Endereço de gateway inválido. Clique em OK para continuar." 8 78			
		fi
	else
		continue
	fi
done          
exitstatus=$?
if [ $exitstatus != 0 ]; then
    echo "Cancelado."
    exit
fi



#------------------------------------------------------------------------------------------------------------------------
# Apresentando a configuração para o usuário
#------------------------------------------------------------------------------------------------------------------------
echo "              Configuração do Domínio" > /root/planilha.txt
echo " " >> /root/planilha.txt
echo "AD DC Hostname: "$Hostname >> /root/planilha.txt
echo "Realm: "$Realm >> /root/planilha.txt
echo "AD DNS: "$Domain >> /root/planilha.txt
echo "Server Role: DC" >> /root/planilha.txt
echo "Backend DNS: BIND9 DLZ" >> /root/planilha.txt
echo "Fully Qualified Domain Name (FQDN): "$FQDN >> /root/planilha.txt
echo "Endereço IP do Servidor: "$End_IP >> /root/planilha.txt
echo "Forwarder DNS Server: "$End_dns >> /root/planilha.txt
echo "Gateway: "$End_gw >> /root/planilha.txt
echo "Mascara de rede: /"$Mcdr >> /root/planilha.txt

whiptail --textbox /root/planilha.txt 19 80




#------------------------------------------------------------------------------------------------------------------------
# Configurando a Rede no Servidor
# apagando ocorrências para acrescentar depois ocorrências: NM_CONTROLLED USERCTL e DOMAIN
#------------------------------------------------------------------------------------------------------------------------
sed -i '/NM_CONTROLLED/d; /ONBOOT/d; /USERCTL/d; /DOMAIN/d; /BOOTPROTO/d; /IPADDR/d; /PREFIX/d; /GATEWAY/d; /DNS1/d; /DNS2/d ' /etc/sysconfig/network-scripts/ifcfg-$Placa

exitstatus=$?
if [ $exitstatus != 0 ]; then
    whiptail --title "ERRO" --msgbox "Erro na configuração de rede. Abortando Instalação. Clique em OK para sair." 8 78
    exit
fi

echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/ifcfg-$Placa
echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/ifcfg-$Placa
echo 'NM_CONTROLLED=no' >> /etc/sysconfig/network-scripts/ifcfg-$Placa
echo 'USERCTL=no' >> /etc/sysconfig/network-scripts/ifcfg-$Placa
echo "DOMAIN=$Realm" >> /etc/sysconfig/network-scripts/ifcfg-$Placa
echo "IPADDR=$End_IP" >> /etc/sysconfig/network-scripts/ifcfg-$Placa
echo "PREFIX=$Mcdr" >> /etc/sysconfig/network-scripts/ifcfg-$Placa
echo "GATEWAY=$End_gw" >> /etc/sysconfig/network-scripts/ifcfg-$Placa
echo "DNS1=$End_IP" >> /etc/sysconfig/network-scripts/ifcfg-$Placa
echo "DNS2=$End_dns" >> /etc/sysconfig/network-scripts/ifcfg-$Placa





#------------------------------------------------------------------------------------------------------------------------
# /etc/hosts e associar o configurar o FQDN


sed -i "/$End_IP/d" /etc/hosts
exitstatus=$?
if [ $exitstatus != 0 ]; then
    whiptail --title "ERRO" --msgbox "Erro configurando o arquivo hosts. Abortando Instalação. Clique em OK para sair." 8 78
    exit
fi
echo "$End_IP    $FQDN  $Hostname" >> /etc/hosts


echo "$Hostname" > /etc/hostname


#------------------------------------------------------------------------------------------------------------------------
# Editar /etc/sysconfig/network
#

# apagando ocorrências para acrescentar depois ocorrências: NETWORKING e HOSTNAME
sed -i '/NETWORKING/d; /HOSTNAME/d ' /etc/sysconfig/network
exitstatus=$?
if [ $exitstatus != 0 ]; then
    whiptail --title "ERRO" --msgbox "Erro configurando o hostname. Abortando Instalação. Clique em OK para sair." 8 78
    exit
fi
echo 'NETWORKING=yes' >> /etc/sysconfig/network
echo 'HOSTNAME='"$Hostname" >> /etc/sysconfig/network



#------------------------------------------------------------------------------------------------------------------------
# Aplica configuração
#

systemctl restart network

ip addr
ip -o link

#------------------------------------------------------------------------------------------------------------------------
# Atualização do SOR Oracle Linux
# MELHORAR: após o update ele faz o reboot e 'crash' o script

cd
curl http://oraclelinux.ctim.mb/mb-config-update.sh > mb-config-update.sh && chmod +x mb-config-update.sh && ./mb-config-update.sh
exitstatus=$?
if [ $exitstatus != 0 ]; then
    whiptail --title "ERRO" --msgbox "Erro no update do Oracle Linux. Abortando Instalação. Clique em OK para sair." 8 78
    exit
fi
cat "" > /etc/yum.repos.d/public-yum-ol7.repo



#------------------------------------------------------------------------------------------------------------------------
# Serviço Secure Shell (SSH) - “/etc/ssh/sshd_config”

if [ -f /etc/ssh/sshd_config ]; then
#	echo "existe"
	sed -i 's/^#Protocol 2.*/Protocol 2/' /etc/ssh/sshd_config
	sed -i '/^Protocol 2/a Ciphers 3des-cbc,blowfish-cbc,cast128-cbc,aes128-cbc,aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com'  /etc/ssh/sshd_config
	sed -i '/^Ciphers 3/a MACs hmac-sha1' /etc/ssh/sshd_config
else
	whiptail --title "ERRO" --msgbox "Arquivo sshd_config não existe. Clique em OK para continuar." 8 78
fi

#------------------------------------------------------------------------------------------------------------------------
# Instalação do Antivírus

yum install bind-utils ed net-tools -y



#------------------------------------------------------------------------------------------------------------------------
# Instalação do SAMBA 4

sudo yum -y groupinstall 'development tools'
exitstatus=$?
if [ $exitstatus != 0 ]; then
    whiptail --title "ERRO" --msgbox "Erro instalando os pacotes de desenvolvimento. Abortando Instalação. Clique em OK para sair." 8 78
    exit
fi


#------------------------------------------------------------------------------------------------------------------------
# Editar o arquivo /etc/krb5.conf para que ele tenha somente as seguintes linhas:
# PRIMEIRO ECHO LIMPA O ARQUIVO E AS DEMAIS ACRESCENTAM LINHAS

echo '[libdefaults]' > /etc/krb5.conf
echo '	default_realm = '$(echo $Realm | tr '[:lower:]' '[:upper:]') >> /etc/krb5.conf
echo '	dns_lookup_realm = false' >> /etc/krb5.conf
echo '	dns_lookup_kdc = true' >> /etc/krb5.conf


#------------------------------------------------------------------------------------------------------------------------
# editar o arquivo /etc/sysctl.conf acrescentando a linha:

echo 'vm.swappiness=0' >> /etc/sysctl.conf 


#------------------------------------------------------------------------------------------------------------------------
# editar o arquivo /etc/selinux/config e setar SELINUX=disabled

linha=$(grep ^"SELINUX=" /etc/selinux/config)
exitstatus=$?

if [ $exitstatus = 0 ]; then
	sed -i "s/$linha/SELINUX=disabled/" /etc/selinux/config
else
	echo 'SELINUX=disabled' >> /etc/selinux/config
fi


#------------------------------------------------------------------------------------------------------------------------
# configuração do firewall

firewall-cmd --permanent --add-port=53/tcp
firewall-cmd --permanent --add-port=53/udp
firewall-cmd --permanent --add-port=88/tcp
firewall-cmd --permanent --add-port=88/udp
firewall-cmd --permanent --add-port=123/udp
firewall-cmd --permanent --add-port=135/tcp
firewall-cmd --permanent --add-port=137/udp
firewall-cmd --permanent --add-port=389/udp
firewall-cmd --permanent --add-port=389/tcp
firewall-cmd --permanent --add-port=445/tcp
firewall-cmd --permanent --add-port=464/tcp
firewall-cmd --permanent --add-port=464/udp
firewall-cmd --permanent --add-port=1024-5000/tcp
firewall-cmd --permanent --add-port=3268/tcp
firewall-cmd --permanent --add-port=8081/tcp
firewall-cmd --permanent --add-port=55443/tcp


#----------------------------------------- -------------------------------------------------------------------------------
# Instalação das dependências

yum install openldap-devel pam-devel git gcc make wget libacl-devel libblkid-devel gnutls-devel readline-devel python-devel cups-devel libaio-devel quota-devel ctdb-devel krb5-devel krb5-workstation acl setroubleshoot-server \
setroubleshoot-plugins policycoreutils-python libsemanage-python  setools-libs popt-devel libpcap-devel libidn-devel libxml2-devel libacl-devel libsepol-devel libattr-devel keyutils-libs-devel cyrus-sasl-devel cups-devel bind-utils \
bind-sdb bind-devel bind-libs bind avahi-devel gamin libcap-devel glusterfs-devel python-dns pkgconfig gdb e2fsprogs-devel zlib-devel sqlite-devel perl attr acl ntp bind bind-sdb quotatool -y

exitstatus=$?
if [ $exitstatus != 0 ]; then
    whiptail --title "ERRO" --msgbox "Erro na instalação das dependências do SAMBA. Abortando Instalação. Clique em OK para sair." 8 78
    exit
fi

#------------------------------------------------------------------------------------------------------------------------
# Configuração do NTP - Modificar o arquivo /etc/ntp.conf acrescentando a linha: server $End_ntp iburst prefer 
# Comentar ou apagar as seguintes linhas do arquivo: server 0.rhel.pool.ntp.org iburst , server 1.rhel.pool.ntp.org iburst
# server 2.rhel.pool.ntp.org iburst , server 3.rhel.pool.ntp.org iburst

sed -i "s/server 0\.rhel\.pool\.ntp\.org iburst/server $End_ntp  iburst prefer/; /server 1/d; /server 2/d; /server 3/d " /etc/ntp.conf 
exitstatus=$?
if [ $exitstatus != 0 ]; then
    whiptail --title "ERRO" --msgbox "Erro configurando o NTP. Abortando Instalação. Clique em OK para sair." 8 78
    exit
fi

systemctl enable ntpd
systemctl start ntpd




echo $Realm" "$Domain" "$Password" "$Naddr" "$Mcdr" "$End_dns > /root/parametros.txt

}  #antes_reboot
#========================================================================================================================
# FINAL do antes do reboot
#========================================================================================================================





#========================================================================================================================
# Início Depois do reboot
#========================================================================================================================

depois_reboot ()
{

Realm=''
Domain=''
Password=''
Naddr=1.1.1.1
Mcdr=20
End_dns=1.1.1.1
if [ -f "/root/parametros.txt" ]; then
	ler_parametro
else
	whiptail --title "ERRO" --msgbox "OOPS algo deu errado. Abortando Instalação. Clique em OK para sair. COD:par" 8 78
	limpa_ambiente
	exit
fi


#------------------------------------------------------------------------------------------------------------------------
#Compilando o SAMBA 4
#Acessar a página do CTIM e baixar o samba dentro do diretório /opt. Descompacte o
#arquivo com o comando   tar -zxvf samba-x.y.z.tar.gz    (x.y.z se refere a versão do SAMBA
#disponibilizada). Entre na pasta criada pela descompactação para compilar o SAMBA 4 com
#os seguintes comandos:

cd /opt
curl http://www.ctim.mb/sites/default/files/aplicacoes/samba-latest.tar.gz > /opt/samba-latest.tar.gz && cd /opt && tar -zxvf samba-latest.tar.gz
Diretorio=$(find . -type d | cut -f2 -d"/" | sort | uniq | grep samba)

cd $Diretorio

./configure.developer
make
make install 


# configuração do ambiente SAMBA

export PATH=$PATH:/usr/local/samba/sbin:/usr/local/samba/bin
echo 'export PATH=$PATH:/usr/local/samba/sbin:/usr/local/samba/bin' >> /root/.bashrc


#Criação do Domínio
#Após a compilação do SAMBA 4, o passo seguinte é a criação do Domínio executando o o seguinte comando:

#/usr/local/samba/bin/samba-tool domain provision --use-rfc2307 --interactive

samba-tool domain provision --server-role=dc --use-rfc2307 --dns-backend=BIND9_DLZ --realm=$Realm --domain=$Domain --server-role=dc --adminpass=$Password 

# Arquivo /etc/rc.d/init.d/samba4



if [ -f /usr/local/samba/etc/smb.conf ]; then
#	 "existe" e cria o serviço no init

    echo '#!/bin/bash' > /etc/rc.d/init.d/samba4
    echo '#' >> /etc/rc.d/init.d/samba4
    echo '# samba4        This shell script takes care of starting and stopping' >> /etc/rc.d/init.d/samba4
    echo '#               samba4 daemons.' >> /etc/rc.d/init.d/samba4
    echo '#' >> /etc/rc.d/init.d/samba4
    echo '# chkconfig: - 58 74' >> /etc/rc.d/init.d/samba4
    echo '# description: Samba 4.0 will be the next version of the Samba suite' >> /etc/rc.d/init.d/samba4
    echo '# and incorporates all the technology found in both the Samba4 alpha' >> /etc/rc.d/init.d/samba4
    echo '# series and the stable 3.x series. The primary additional features' >> /etc/rc.d/init.d/samba4
    echo '# over Samba 3.6 are support for the Active Directory logon protocols' >> /etc/rc.d/init.d/samba4
    echo '# used by Windows 2000 and above.' >> /etc/rc.d/init.d/samba4
    echo ' ' >> /etc/rc.d/init.d/samba4
    echo '### BEGIN INIT INFO' >> /etc/rc.d/init.d/samba4
    echo '# Provides: samba4' >> /etc/rc.d/init.d/samba4
    echo '# Required-Start: $network $local_fs $remote_fs' >> /etc/rc.d/init.d/samba4
    echo '# Required-Stop: $network $local_fs $remote_fs' >> /etc/rc.d/init.d/samba4
    echo '# Should-Start: $syslog $named' >> /etc/rc.d/init.d/samba4
    echo '# Should-Stop: $syslog $named' >> /etc/rc.d/init.d/samba4
    echo '# Short-Description: start and stop samba4' >> /etc/rc.d/init.d/samba4
    echo '# Description: Samba 4.0 will be the next version of the Samba suite' >> /etc/rc.d/init.d/samba4
    echo '# and incorporates all the technology found in both the Samba4 alpha' >> /etc/rc.d/init.d/samba4
    echo '# series and the stable 3.x series. The primary additional features' >> /etc/rc.d/init.d/samba4
    echo '# over Samba 3.6 are support for the Active Directory logon protocols' >> /etc/rc.d/init.d/samba4
    echo '# used by Windows 2000 and above.' >> /etc/rc.d/init.d/samba4
    echo '### END INIT INFO' >> /etc/rc.d/init.d/samba4
    echo ' ' >> /etc/rc.d/init.d/samba4
    echo '# Source function library.' >> /etc/rc.d/init.d/samba4
    echo '. /etc/init.d/functions' >> /etc/rc.d/init.d/samba4
    echo ' ' >> /etc/rc.d/init.d/samba4
    echo '# Source networking configuration.' >> /etc/rc.d/init.d/samba4
    echo '. /etc/sysconfig/network' >> /etc/rc.d/init.d/samba4
    echo ' ' >> /etc/rc.d/init.d/samba4
    echo 'prog=samba' >> /etc/rc.d/init.d/samba4
    echo 'prog_dir=/usr/local/samba/sbin/' >> /etc/rc.d/init.d/samba4
    echo 'lockfile=/var/lock/subsys/$prog' >> /etc/rc.d/init.d/samba4
    echo ' ' >> /etc/rc.d/init.d/samba4
    echo 'start() {' >> /etc/rc.d/init.d/samba4
    echo '        [ "$NETWORKING" = "no" ] && exit 1' >> /etc/rc.d/init.d/samba4
    echo '#       [ -x /usr/sbin/ntpd ] || exit 5' >> /etc/rc.d/init.d/samba4
    echo '                # Start daemons.' >> /etc/rc.d/init.d/samba4
    echo '                echo -n $"Starting samba4: "' >> /etc/rc.d/init.d/samba4
    echo '                daemon $prog_dir/$prog -D' >> /etc/rc.d/init.d/samba4
    echo '        RETVAL=$?' >> /etc/rc.d/init.d/samba4
    echo '                echo' >> /etc/rc.d/init.d/samba4
    echo '        [ $RETVAL -eq 0 ] && touch $lockfile' >> /etc/rc.d/init.d/samba4
    echo '        return $RETVAL' >> /etc/rc.d/init.d/samba4
    echo '}' >> /etc/rc.d/init.d/samba4
    echo 'stop() {' >> /etc/rc.d/init.d/samba4
    echo '        [ "$EUID" != "0" ] && exit 4' >> /etc/rc.d/init.d/samba4
    echo '                echo -n $"Shutting down samba4: "' >> /etc/rc.d/init.d/samba4
    echo '        killproc $prog_dir/$prog' >> /etc/rc.d/init.d/samba4
    echo '        RETVAL=$?' >> /etc/rc.d/init.d/samba4
    echo '                echo' >> /etc/rc.d/init.d/samba4
    echo '        [ $RETVAL -eq 0 ] && rm -f $lockfile' >> /etc/rc.d/init.d/samba4
    echo '        return $RETVAL' >> /etc/rc.d/init.d/samba4
    echo '}' >> /etc/rc.d/init.d/samba4
    echo '# See how we were called.' >> /etc/rc.d/init.d/samba4
    echo 'case "$1" in' >> /etc/rc.d/init.d/samba4
    echo 'start)' >> /etc/rc.d/init.d/samba4
    echo '        start' >> /etc/rc.d/init.d/samba4
    echo '       ;;' >> /etc/rc.d/init.d/samba4
    echo 'stop)' >> /etc/rc.d/init.d/samba4
    echo '        stop' >> /etc/rc.d/init.d/samba4
    echo '      ;;' >> /etc/rc.d/init.d/samba4
    echo 'status)' >> /etc/rc.d/init.d/samba4
    echo '        status $prog' >> /etc/rc.d/init.d/samba4
    echo '       ;;' >> /etc/rc.d/init.d/samba4
    echo 'restart)' >> /etc/rc.d/init.d/samba4
    echo '        stop' >> /etc/rc.d/init.d/samba4
    echo '        start' >> /etc/rc.d/init.d/samba4
    echo '       ;;' >> /etc/rc.d/init.d/samba4
    echo 'reload)' >> /etc/rc.d/init.d/samba4
    echo '        echo "Not implemented yet."' >> /etc/rc.d/init.d/samba4
    echo '        exit 3' >> /etc/rc.d/init.d/samba4
    echo '       ;;' >> /etc/rc.d/init.d/samba4
    echo '*)' >> /etc/rc.d/init.d/samba4
    echo '        echo $"Usage: $0 {start|stop|status|restart|reload}"' >> /etc/rc.d/init.d/samba4
    echo '        exit 2' >> /etc/rc.d/init.d/samba4
    echo 'esac' >> /etc/rc.d/init.d/samba4

else
	whiptail --title "ERRO" --msgbox "Erro na criação do Domínio. Abortando Instalação. Clique em OK para sair." 8 78
	limpa_ambiente
	exit
fi





# Executar os seguintes comandos para que o script acima seja executado automaticamente na inicialização do Oracle Linux:

chmod 755 /etc/rc.d/init.d/samba4
chmod +x /etc/rc.d/init.d/samba4 
ln -s /etc/rc.d/init.d/samba4 /etc/rc3.d/S80samba4
chkconfig --add samba4
systemctl start samba4 
systemctl enable samba4


# Configurando o Backup : https://wiki.samba.org/index.php/Back_up_and_Restoring_a_Samba_AD_DC

if [ -f "/usr/sbin/samba_backup" ]; then
    rm -f /usr/sbin/samba_backup
fi

cp /opt/$Diretorio/source4/scripting/bin/samba_backup /usr/sbin
chown root:root /usr/sbin/samba_backup
chmod 750 /usr/sbin/samba_backup


cat /usr/sbin/samba_backup | grep -E ^FROMWHERE=.* > null
exitstatus=$?
if [ $exitstatus = 0 ]; then
	cat /usr/sbin/samba_backup | grep  '\bFROMWHERE=/usr/local/samba\b' > null
	exitstatus=$?
    if [ $exitstatus != 0  ]; then
        sed -i 's/^FROMWHERE=.*/FROMWHERE=\/usr\/local\/samba/'/usr/sbin/samba_backup
    fi
else
    sed -i -e 29'i\' -e 'FROMWHERE=/usr/local/samba' /usr/sbin/samba_backup
fi


cat /usr/sbin/samba_backup | grep -E ^WHERE=.* > null
exitstatus=$?
if [ $exitstatus = 0 ]; then
	cat /usr/sbin/samba_backup | grep  '\bWHERE=/usr/local/backups\b' > null
	exitstatus=$?
    if [ $exitstatus != 0  ]; then
         sed -i 's/^WHERE=.*/WHERE=\/usr\/local\/backups/'/usr/sbin/samba_backup
    fi
else
    sed -i -e 30'i\' -e 'WHERE=/usr/local/backups' /usr/sbin/samba_backup
fi

cat /usr/sbin/samba_backup | grep -E ^DAYS=.* > null
exitstatus=$?
if [ $exitstatus = 0 ]; then
	cat /usr/sbin/samba_backup | grep  '\bDAYS=90\b' > null
	exitstatus=$?
    if [ $exitstatus != 0  ]; then
         sed -i 's/^DAYS=.*/DAYS=90/'/usr/sbin/samba_backup
    fi
else
    sed -i -e 31'i\' -e 'DAYS=90' /usr/sbin/samba_backup
fi

if [ ! -d "/usr/local/backups" ]; then
    mkdir /usr/local/backups
fi

chmod 750 /usr/local/backups

echo '0 2 * * *       /usr/sbin/samba_backup' > /root/bkp.txt
crontab /root/bkp.txt


# /usr/local/samba/etc/smb.conf e acrescentar a seguinte linha na seção [GLOBAL] :

if [ -f "/usr/local/samba/etc/smb.conf" ]; then
	linha=$(grep -m1 -ni GLOBAL aa/sshd_config.conf | cut -f 1 -d \:)
	linha=$( expr $linha + 5 )
	sed -i -e $linha'i\' -e '        hide unreadable = Yes' /usr/local/samba/etc/smb.conf
	sed -i -e $linha'i\' -e '        hide unwriteable files = Yes' /usr/local/samba/etc/smb.conf
	sed -i -e $linha'i\' -e '        restrict anonymous = 2' /usr/local/samba/etc/smb.conf
	sed -i -e $linha'i\' -e '        winbind enum users = Yes' /usr/local/samba/etc/smb.conf
    	sed -i -e $linha'i\' -e '        winbind enum groups = Yes' /usr/local/samba/etc/smb.conf
	sed -i -e $linha'i\' -e '        winbind use default domain = Yes' /usr/local/samba/etc/smb.conf


	

else
	whiptail --title "ERRO" --msgbox "OOPS algo deu errado. Abortando Instalação. Clique em OK para sair. COD:smb" 8 78
	limpa_ambiente
	exit
fi


# Configuração do DNS --- rede-local e o dns
# arquivo /etc/named.conf

echo 'acl rede-local {' > /etc/named.conf
echo '        localhost;' >> /etc/named.conf
echo '        '"$Naddr"'/'"$Mcdr"';' >> /etc/named.conf
echo '};' >> /etc/named.conf
echo 'options {' >> /etc/named.conf
echo '	listen-on port 53 { rede-local; }; ' >> /etc/named.conf
echo '	allow-query     { rede-local; };' >> /etc/named.conf
echo '	tkey-gssapi-keytab "/usr/local/samba/private/dns.keytab";' >> /etc/named.conf
echo '	directory 	"/var/named";' >> /etc/named.conf
echo '	dump-file 	"/var/named/data/cache_dump.db";' >> /etc/named.conf
echo '	statistics-file "/var/named/data/named_stats.txt";' >> /etc/named.conf
echo '	memstatistics-file "/var/named/data/named_mem_stats.txt";' >> /etc/named.conf
echo ' ' >> /etc/named.conf
echo '	recursion yes;' >> /etc/named.conf
echo '	forwarders {' >> /etc/named.conf
echo "		$End_dns;" >> /etc/named.conf
echo '	};' >> /etc/named.conf
echo ' ' >> /etc/named.conf
echo '	dnssec-enable no;' >> /etc/named.conf
echo '	dnssec-validation no;' >> /etc/named.conf
echo '	auth-nxdomain no;    // conform to RFC1035' >> /etc/named.conf
echo '	/* Path to ISC DLV key */' >> /etc/named.conf
echo '	bindkeys-file "/etc/named.iscdlv.key";' >> /etc/named.conf
echo '	managed-keys-directory "/var/named/dynamic";' >> /etc/named.conf
echo '	pid-file "/run/named/named.pid";' >> /etc/named.conf
echo '	session-keyfile "/run/named/session.key";' >> /etc/named.conf
echo '};' >> /etc/named.conf
echo ' ' >> /etc/named.conf
echo 'logging {' >> /etc/named.conf
echo '        channel default_debug {' >> /etc/named.conf
echo '                file "data/named.run";' >> /etc/named.conf
echo '                severity dynamic;' >> /etc/named.conf
echo '        };' >> /etc/named.conf
echo '};' >> /etc/named.conf
echo 'zone "." IN {' >> /etc/named.conf
echo '	type hint;' >> /etc/named.conf
echo '	file "named.ca";' >> /etc/named.conf
echo '};' >> /etc/named.conf
echo ' ' >> /etc/named.conf
echo 'include "/etc/named.rfc1912.zones";' >> /etc/named.conf
echo 'include "/etc/named.root.key";' >> /etc/named.conf
echo 'include "/usr/local/samba/private/named.conf";' >> /etc/named.conf

# Finalizando a configuração executar os seguintes comandos e ao final reiniciar o servidor:

chown named.named /var/named/
systemctl restart named 
systemctl status samba4 
systemctl status named 
systemctl enable named.service



#+++++++++++++++++++++++++++++++++++++

# Após a reinicialização executar os seguintes comandos:

chgrp named /usr/local/samba/private/dns.keytab 
chmod g+r /usr/local/samba/private/dns.keytab 


# Fazer uma atualização de DNS no Samba e verificando se foi atualizado (trocar o Domínio pelo da OM):

/usr/local/samba/sbin/samba_dnsupdate  --verbose

#host -t SRV _ldap._tcp.domain.ad.
#host -t SRV _kerberos._udp.domain.ad.
#host -t A domain.ad.


# Configuração do Kerberos
# Criar um symlink no caminho /etc/krb5.keytab apontando para o arquivo /usr/local/samba/private/dns.keytab e testar com os comandos abaixo

ln -s /usr/local/samba/private/dns.keytab /etc/krb5.keytab

  
# password settings

/usr/local/samba/bin/samba-tool domain passwordsettings set --min-pwd-age=0


}
#========================================================================================================================
# Final do DEPOIS do reboot
#========================================================================================================================

cria_service ()
{
echo '#! /bin/sh' > /etc/init.d/instala-samba
echo " " >> /etc/init.d/instala-samba
echo 'PATH=/sbin:/bin:/usr/sbin:/usr/bin' >> /etc/init.d/instala-samba
echo ' ' >> /etc/init.d/instala-samba
echo 'case "$1" in' >> /etc/init.d/instala-samba
echo '    start)' >> /etc/init.d/instala-samba
echo "        $NOME_SCRIPT" >> /etc/init.d/instala-samba
echo '        ;;' >> /etc/init.d/instala-samba
echo '    stop|restart|reload)' >> /etc/init.d/instala-samba
echo '        ;;' >> /etc/init.d/instala-samba
echo 'esac' >> /etc/init.d/instala-samba

chmod +x /etc/init.d/instala-samba
echo '/etc/init.d/instala-samba start' >> /root/.bashrc

}

#========================================================================================================================
# MAIN
#========================================================================================================================

if [ -f "/root/rebooting-for-updates" ]; then
    depois_reboot
    rm /root/rebooting-for-updates -f
    sed -i '/instala-samba/d ' /root/.bashrc
    rm /root/parametros.txt -f
    reboot
else
    antes_reboot
    cria_service
    touch /root/rebooting-for-updates

    whiptail --title "AVISO" --msgbox "Primeira parte da configuração executada com êxito e seu servidor será reiniciado. Após a reinicialização logar novamente como root para continuar a instalação. Clique em OK para continuar." 10 78

    reboot
fi





