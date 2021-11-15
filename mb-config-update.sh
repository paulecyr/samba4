#!/bin/bash

function msgConfirm { # $1 Titulo, $2 msg
  whiptail --title "$1" --yesno "$2" --fb 10 60
}

function msgError { # $1 msg
  whiptail --title "Erro" --msgbox "$1" --fb 14 60
}

function msgInfo { # $1 msg
  whiptail --title "Informação" --msgbox "$1" --fb 14 60
}


if [ "$EUID" -ne 0 ]
  then msgError "ERRO: Para configurar os repositórios e a atualização automática execute este script como root"
  exit
fi

echo "" >  /etc/yum.repos.d/public-yum-ol7.repo


if [ -f /etc/yum.repos.d/mb-yum-ol7.repo ] 
  then 
	msgInfo "A configuração deste servidor parece já ter sido feita. Nada a executar"
	exit
  else
  	curl http://oraclelinux.ctim.mb/mb-yum-ol7.repo > /etc/yum.repos.d/mb-yum-ol7.repo
	curl http://oraclelinux.ctim.mb/RPM-GPG-KEY-EPEL-7 > /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7
fi

yum check-update

yum -y install yum-cron yum-utils
sed -i "s/apply_updates = no/apply_updates = yes/" /etc/yum/yum-cron.conf
systemctl start yum-cron
systemctl enable yum-cron
package-cleanup --oldkernels --count=2

if grep -q "installonly_limit" "/etc/yum.conf"; then
echo ""
else
echo "installonly_limit=2" >> /etc/yum.conf
fi

msgInfo "A configuração para atualização automática foi realizada para que este servidor se comunique com o repositório e se atualize todos os dias\nSerá feita agora uma tentativa de primeira atualização completa."
#read -p "Será feita agora uma tentativa de primeira atualização completa.\nTecle Enter para iniciar"

yum -y update

msgInfo "Marinha do Brasil\nDiretoria de Comunicações e Tecnologia da Informação da Marinha\n\nConfiguração de repositórios de atualização efetuada com sucesso"

