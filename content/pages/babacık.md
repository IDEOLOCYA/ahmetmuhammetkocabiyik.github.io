Title: Quaoar Vulnerable Machine
Date: 2017- 04 -23
Author: ahmetmuhammetkocabıyık
Category: Vulnhub Solutions
Öncelikle bu benim çözdüğüm ilk sanal zafiyetli makinem. Bu yüzden pekçok şeyi araştırmam gerekti. Önceden arkadaşlarımın çözdükleri makinelere bakarak az buçuk bir şeyler kaptığımı düşünüyordum. Daha önce öğrendiklerimin faydasını yeni yenigördüğümü söyleyebilirim. İlk olarak makineyi ![şu linkten](https://www.vulnhub.com/entry/hackfest2016-quaoar,180/)indirerek VM Player sanallaştırma ortamında ayaklandırdım. Açtığımda beni şöyle bir ekran karşıladı. 

![link to pictures](https://static.pexels.com/photos/165818/pexels-photo-165818.jpeg)

Bu makinenin çözümü üç aşamada gerçekleşti.
İlk adımda, hedef sisteme shell erişimi elde ettim.
İkinci adımda, yetkili kullanıcı haklarına eriştim.
Üçüncü adımda ise post exploitation işlemleri ile flag'i elde ettim.
İlk adımı gerçekleştirebilmek için hedef sistemde açık olan portları ve servisleri nmap aracı ile analiz etmeye başladım. Yaptığım taramanın sonucu şöyle idi: 

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/2.png)

80 portunun açık olduğunu görünce tarayıcım ile ziyarette bulundum. 

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/3.png)

Web sitesi hakkında bir şeyler öğrenmek için Nikto aracı ile tarama yaptım.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/4.png)

Nikto bana robots.txt dosyası bulmuştu, mutlu olup içinde hangi dizinlere hangi izinlerin verildiğine baktım. 

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/5.png)

/wordpress dizinine gittiğimde karşıma Wordpress içerik yönetim sistemi tarafından oluşturulmuş bir blog çıktı. Aynı dizini Dirbuster gibi araçlar ile de bulabilirdik fakat burada robots.txt içeriğini okuyarak zahmet etmeden bu bilgiyi elde etmiş olduk.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/6.png)

Ardından acaba bu aşamayı nasıl geçebilirim diye düşündüm. Kali Linux'taki araçlardan daha önce gördüğüm veya bana 
yardımcı olabilecek bir tool var mı diye biraz araştırma yaptım. Karşıma WPScan çıktı. WPScan'ın nasıl kullanılacağını pek bilmesemde Youtube'da biraz araştırma ile işime yarayabilecek bir kaç komut buldum ve taradım bizim linki.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/7.png)

WPScan'den gelen sonuca göre bu makineyi oluşturan arkadaş öntanımlı kullanıcı adı ve parolayı değiştirmemiş.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/7.1.png)

Elde ettiğim admin/admin kullanıcı adı ve parola ikilisi ile panele("http://192.168.1.106/wordpress/wp-login.php")  [URL'deki 192.168.1.106 kısmı makinenin aldığı ip] giriş yapabildim. Şimdi hedef sisteme shell erişimi elde etmek için neler yapabiliriz onu düşünmek kaldı. Elimde yönetici paneline yetkili kullanıcı ile erişim elde edebildiğim bir wordpress sitesi vardı. Bende geçmiş tecrübelerime dayanarak php shell'e yöneldim. Tarayıcı üzerinden erişebildiğim bir yere sistem komutları çalıştırabileceğim ya da doğrudan sisteme bağlantı elde edebileceğim zararlı bir php dosyası üretmem gerekiyordu. Bunun için de "msfvenom" aracını kullandım.  

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/8.png)

Ardından, wordpress panelinde tema ayarlarından son kullanıcıya gösterilen 404 hata sayfasının kodlarına küçük bir müdahalede bulunarak bir önceki aşamada msfvenom ile ürettiğim zararlı php kodunu buraya yapıştırdım. Böylelikle sitede varolmayan bir URL'e ulaşmak istediğimde Wordpress bana bu 404 sayfasını dönecekti. Yani benim zararlı kodum çalışacaktı.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/9.png)

Bu aşamada, var olmayan bir URL'e istekte bulunduğumda wordpress bana 404 hata sayfasını dönecekti. 404 hata sayfasının değiştirilmiş içeriğinde ise sistemime doğrudan bağlantı isteği gönderecek php kodu vardı. Yani benim önce dinlemeye geçmem lazım ki 404 hata sayfasına istek gönderdiğimde, php kodu çalışıp bana ulaşabilsin. Bu nedenle Metasploit Framework içerisinde bulunan exploit/multi/handler modülünü msfvenom ile oluşturduğum php shell'e göre ayarladım.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/10.png)

Ziyaret ettiğim sayfa bana 404 hatasının msfconsola ulaşmadığını görüp dinlemeye başladım.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/11.png)

Handler bağlantıyı yakaladı!

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/12.png)

Geriye iki adım kaldı. İlki çok vakit almıştı şimdi hedef ikincisindeydi "root olmak" bunun için web sitesine
biraz gözgezdirdim. Meterpreter erişimi üzerinden ilerlemeye karar verdim. python -c 'import pty;pty.spawn("/bin/bash")'  komutu ile etkileşimli shell'e geçerek daha rahat hareket etmeye başladım ve sistemin içinde bulunan konfigürasyon dosyalarını incelemeye başladım.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/13.png)

Bu basit bir makine dedim kendi kendime... Çok kapsamlı düşünmeye gerek yok ya oradadır ya burada diye düşünüp, 2 yaşındaki misafir çocuğu edasıyla makinenin içindeki her dosyayı açıp kapatıp oynarken, karşıma bir şey daha geldi. 

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/14.png)

Hemen ardından gelen hunharca kahkahayıda unutmamalı. İşte parola:

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/15.png)

Bulduğum şifre ve parolayı kullanarak yalnız parolanın sonundaki ünlem işaretini unutmadığıma emin olarak root oluyorum.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/16.png)

Şimdi sadece flag'i bulmak  kaldı. Makinede root oluduğumda bulunduğum dizini kontrol ediyorum. Beni flag karşılıyor.

![link to pictures](https://github.com/ahmetmuhammetkocabiyik/Vulnerable-Machines-Solutions/blob/master/Quaoar%20Vulnerable%20Machines/Quaoar%20Pictures/17.png)

Bu makinede böyle hüzünlü bir sonla bitiyor daha nice makinelerde görüşmek üzere ...

