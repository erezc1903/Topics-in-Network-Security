#!/bin/bash

echo "Setting up proxy..."
sudo a2enmod proxy
sudo a2enmod proxy_http
sudo a2enmod proxy_connect
sudo cp ports.conf /etc/apache2/
sudo cp proxy.conf /etc/apache2/mods-available/
sudo cp forward_proxy.conf /etc/apache2/sites-available/
sudo a2ensite forward_proxy.conf
sudo /etc/init.d/apache2 restart
echo "Proxy setup done"
echo "Setting up module..."
sudo cp BlackList.txt /var/www/html/
sudo cp virus_block_log.txt /var/www/html/
sudo chmod 777 /var/www/html/BlackList.txt /var/www/html/virus_block_log.txt
sudo cp virus_block.conf /etc/apache2/mods-available/
sudo apxs -i -a -c mod_virus_block.c
sudo a2enmod virus_block
sudo /etc/init.d/apache2 restart
echo "Module setup done"