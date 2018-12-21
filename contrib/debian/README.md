
Debian
====================
This directory contains files used to package basexd/basex-qt
for Debian-based Linux systems. If you compile basexd/basex-qt yourself, there are some useful files here.

## basex: URI support ##


basex-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install basex-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your basexqt binary to `/usr/bin`
and the `../../share/pixmaps/basex128.png` to `/usr/share/pixmaps`

basex-qt.protocol (KDE)

