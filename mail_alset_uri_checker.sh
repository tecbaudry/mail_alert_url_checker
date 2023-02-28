#!/bin/bash
#
# Copyright (C) 20230228 Tomas Cardozo
# This file is part of mail_alset_uri_check <https://github.com/tecbaudry/mail_alert_url_checker>.
#
# mail_alset_uri_check is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# mail_alset_uri_check is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with mail_alset_uri_check.  If not, see <http://www.gnu.org/licenses/>.

### THIS APPLICATION BASH MAKES A 3 STEPS URL CHECK PING SSL VALIDATION AND WEB RENDER STATUS
### OU CAN CHANGE SERVER URL, VALID MAIL PARAMETERSS,  AND AFTER PUT IN A CRON SCHEDULER FOR RUN PERIODICALLY

v0_config_server_url="";                  ### url a ser verificada


v0_config_subject="Alerta web ";                                   ### asunto del mensaje
v0_config_message="Se han detectado: ";                            ### mensaje del correo
####################################################################
v0_config_host_name="servidor";                                    ### direccion del servidor de correo
####################################################################
v0_config_host_port="587";                                         ### puerto de acceso del servidor de correo
v0_config_host_string="$v0_config_host_name:$v0_config_host_port"; ### parametro de servidor
v0_config_host_method="login";                                     ### metodo de autenticacion
v0_config_host_username="usuario servidor";                        ### user servicio
v0_config_host_userpass="contrasena servidor";                     ### pass servicio
v0_config_sender_address="remitente@correo.ejemplo";               ### direccion remitente
v0_config_destiny_address="destinatario@correo.ejemplo";           ### direccion destinatario
####################################################################


function f_mail_sender () {
  v4_sender_subject="$1";         v4_sender_message="$2";
  v4_config_server_url="$3";      v4_config_server_name=$(echo $v1_config_server_url | cut -d '/' -f 3);
  v4_sender_host_string="$4";     v4_sender_host_method="$5";
  v4_sender_host_username="$6";   v4_sender_host_userpass="$7";
  v4_sender_address="$8";         v4_config_destiny_address="$9";
  ####################################################################
  v4_sender_receivers="$9";                     ### destinatario
  ####################################################################
  echo "$v4_sender_message" | mailx -v -s "$v4_sender_subject"  -r "$v4_sender_address"  -S smtp="$v4_sender_host_string" -S smtp-auth="$v4_sender_host_method" -S smtp-auth-user="$v4_sender_host_username" -S smtp-auth-password="$v4_sender_host_userpass" $v4_sender_receivers ;
}


function f_html_test () {
    v2_config_server_url=$1
    v2_output3=$(curl --insecure -L -vvI $v2_config_server_url 2>&1 | grep "403 Forbidden"); 
    v2_output4=$(curl --insecure -L -vvI $v2_config_server_url 2>&1 | grep "404 Not Found"); 
    if [[ $v2_output3 == *"403 Forbidden"* ]] ; then  v2_html_status3=1; else v2_html_status3=0; fi 
    if [[ $v2_output4 == *"404 Not Found"* ]] ; then  v2_html_status4=1; else v2_html_status4=0; fi 
    v2_html_status=$((v2_html_status3 + v2_html_status4))
    if [ "$v2_html_status" -ne "0" ]; then
      v_html_status=1; 
      v_html_message="El servidor '$v2_config_server_url' no despliega la web correctamente. ";
    else
      v_html_status=0; 
      v_html_message="El servidor '$v2_config_server_url' despliega la web correctamente. ";
    fi
}


function f_ping_ssl_html_test () {
  v1_sender_subject="$1";         v1_sender_message="$2";
  v1_config_server_url="$3";      v1_config_server_name=$(echo $v1_config_server_url | cut -d '/' -f 3);
  v1_sender_host_string="$4";     v1_sender_host_method="$5";
  v1_sender_host_username="$6";   v1_sender_host_userpass="$7";
  v1_sender_address="$8";         v1_config_destiny_address="$9";
  #####################################################################
  if [[ $(ping -q -c2 $v1_config_server_name) ]]; then
    v_ping_status=0;
    v_ping_message="El servidor '$v1_config_server_url' se encuentra activo. ";
    ###################################################################
    v1_output0=$(curl --insecure -vvI $v1_config_server_url 2>&1 | awk 'BEGIN { cert=0 } /^\* SSL connection/ { cert=1 } /^\*/ { if (cert) print }' | grep "self signed"); 
    v1_output1=$(curl --insecure -vvI $v1_config_server_url 2>&1 | awk 'BEGIN { cert=0 } /^\* Connected to/ { cert=1 } /^\*/ { if (cert) print }' | grep "SSL_ERROR_SYSCALL"); 
    if [[ $v1_output0 == *"self signed"* ]] ; then  v1_ssl_status0=0; else v1_ssl_status0=1; fi 
    if [[ $v1_output1 == *"SSL_ERROR_SYSCALL"* ]] ; then  v1_ssl_status1=0; else v1_ssl_status1=1; fi 
    v1_ssl_status=$((v1_ssl_status0 + v1_ssl_status1))
    if [ "$v1_ssl_status" -ne "0" ]; then
      v_ssl_status=1; 
      v_ssl_message="El certificado del servidor '$v1_config_server_url' no es valido. ";
      f_html_test $v1_config_server_url
    else
      v_ssl_status=0; 
      v_ssl_message="El certificado del servidor '$v1_config_server_url' es valido. ";
      f_html_test $v1_config_server_url
    fi 
    ###################################################################
  else
    v_ping_status=1;
    v_ping_message="El servidor '$v1_config_server_url' se encuentra inactivo o inaccesible. ";
    v_ssl_message=" ";
    v_html_message=" ";
  fi
  #####################################################################

  #####################################################################
  v_server_status=$((v_ping_status + v_ssl_status + v_html_status))
  if [ "$v1_ssl_status" -ne "0" ]; then
    ### alguno de loss checkeos devuelve error;
    ### falataria afinar y checkar mas mensajes del servidor web y el servicio del sistema, dependiendo la version y distribucion del os
    v_mail_message=" PING: "$v_ping_message"; SSL: "$v_ssl_message" ; HTTP RENDER: "$v_html_message" ";
    v_config_subject="$v1_sender_subject $v1_config_server_url";
    v_config_message="$v1_sender_message $v_mail_message";
    f_mail_sender "$v_config_subject" "$v_config_message" "$v1_config_server_url" "$v1_sender_host_string" "$v1_sender_host_method" "$v1_sender_host_username" "$v1_sender_host_userpass" "$v1_sender_address" "$v1_config_destiny_address" ;
  else
    ### no se encuentra ningun problema
    v="";
  fi
  

}

f_ping_ssl_html_test "$v0_config_subject" "$v0_config_message" "$v0_config_server_url" "$v0_config_host_string" "$v0_config_host_method" "$v0_config_host_username" "$v0_config_host_userpass" "$v0_config_sender_address" "$v0_config_destiny_address" ;
