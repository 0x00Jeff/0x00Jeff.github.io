---
layout: post
title: 'Install Ruby on Rails di Linux Ubuntu'
date: 2017-04-18
categories: tutorials
tags: ruby rails
cover: 'https://s3.gifyu.com/images/sonpnKqslhM.jpg'
---

Tutorial Menggunakan Bahasa Indonesia dan Russia(учебник с индонезийской и русском языках)

Maaf jika tutorial kurang jelas, atau ada yang salah silahkan dikoreksi (К сожалению, если учебник менее ясно, или есть что-то не так, пожалуйста, исправить)

## ALASAN
mengapa ruby on rails ?  karena framework ruby on rails , MVC dan bahasa ruby sangat elegan dan enak dipandang, mungkin :) . tenang, gampang kok instal ruby dan ruby on rails di Ubuntu 
(почему ruby on rails ? потому что рамки ruby on rails с MVC рубиновое кодирование очень элегантные и приятной для глаз, может :) . тихий, очень легко Интал рубин и ruby on rails в Ubuntu ) 

jadi gak usah banyak kata, langsung aja kita mulai (так что не нужно много слов, прямо в точку, мы начали) : 

## PERSIAPAN (ПОДГОТОВКА) 
-Koneksi Internet Stabil (Стабильное подключение к Интернету)

-Akses Root (доступ root)

-Sudah terinstal Curl (уже установлен Curl)

```css
$ sudo apt-get install curl
```


## INSTAL RUBY DENGAN RVM (УСТАНОВИТЬ RUBY С RVM)  
rvm adalah ruby version manager . fungsinya untuk memanage versi dari ruby dan rails. 
keuntunganya kita bisa berganti versi dari ruby dan rails dengan mudah dan gak ribet (RVM является менеджером рубина версии. функция управления версии рубин и рельсов. 
преимущество, что мы можем изменить версию рубином и рельсы с легким и не сложно)
```css
$ \curl -L https://get.rvm.io | bash -s stable --ruby
```


update rvm dan instal ruby, disini saya menggunakan ruby versi 2.4.0 (обновление RVM и установить рубин, здесь я использую рубин версии 2.4.0)
```css
$ rvm get stable --autolibs=enable
```  
```css
$ rvm install ruby
```  
```css
$ rvm --default use ruby-2.4.0
``` 


cek ruby sudah terinstal (рубин проверяет уже установлен)
```css
$ ruby -v
``` 


cek gem (проверить камень)
```css
$ gem -v
``` 


update gem (обновления драгоценный камень)
```css
$ gem update --system
``` 


set rvm global gemset dan gem yg ada (множество глобальной RVM gemset и камень мыслимого)
```css
$ rvm gemset use global
```  
```css
$ gem list
``` 


instal rails dengan ruby gems (установить рельсы с рубиновыми камнями)
```css
$ gem install rails
``` 
    
cek rails sudah teinstal (проверить рельсы уже)
```css
$ rails -v
``` 

selesai . kita sudah menginstal ruby dan ruby on rails :) 
kita sudah bisa buat project atau aplikasi dengan ruby on rails 
(завершено. мы установили рубин и ruby on rails :) 
мы были в состоянии создать проект или приложение с ruby on rails) 


## BUAT PROJECT BARU DENGAN RUBY ON RAILS (СОЗДАТЬ НОВЫЙ ПРОЕКТ С RUBY ON RAILS)  

buat direktori baru (создать новый каталог)
```css
$ mkdir project_rubyonrails
``` 


masuk direktori project_rubyonrails (запись каталога project_rubyonrails)
```css
$ cd project_rubyonrails
``` 


buat project baru ruby on rails (создать новый проект ruby on rails)
```css
$ rails new appku
``` 


masuk direktori project appku (войти в каталог appku проекта)
```css
$ cd appku
``` 


test server (тестовый сервер)
```css
$ rails s
``` 


buka browser dan ketik di address bar (откройте браузер и введите в адресной строке)
```css
http://localhost:3000
``` 

jika tidak ada masalah . akan seperti gambar dibawah (если нет никаких проблем. будет, как показано ниже) 


![sucess](https://s3.gifyu.com/images/eNjSzlZ8UOw.jpg)




