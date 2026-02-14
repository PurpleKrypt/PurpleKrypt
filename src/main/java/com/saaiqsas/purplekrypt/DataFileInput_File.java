package com.saaiqsas.purplekrypt;

import javafx.beans.property.SimpleStringProperty;

/*
    PurpleKrypt Graphical Tool is Licensed under The GNU GPLv3
    +-----------------------------------------------------------------------+
    | PurpleKrypt -                                                         |
    | An encryption tool for text and file encryption, utilizing the        |
    | AES-256-GCM algorithm. It supports keyfiles and passwords via         |
    | Argon2id key derivation                                               |
    |                                                                       |
    | Copyright (C) 2025-Present Saaiq Abdulla Saeed (saaiqSAS)             |
    |                                                                       |
    | This program is free software: you can redistribute it and/or modify  |
    | it under the terms of the GNU General Public License as published by  |
    | the Free Software Foundation, either version 3 of the License, or     |
    | (at your option) any later version.                                   |
    |                                                                       |
    | This program is distributed in the hope that it will be useful,       |
    | but WITHOUT ANY WARRANTY; without even the implied warranty of        |
    | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the          |
    | GNU General Public License for more details.                          |
    |                                                                       |
    | You should have received a copy of the GNU General Public License     |
    | along with this program. If not, see <https://www.gnu.org/licenses/>. |
    |                                                                       |
    | For support or to contact the author:                                 |
    | Email: purplekrypt@gmail.com                                          |
    +-----------------------------------------------------------------------+
*/

public class DataFileInput_File {

    private final SimpleStringProperty ID;
    private final SimpleStringProperty type;
    private final SimpleStringProperty path;
    private final SimpleStringProperty name;

    public DataFileInput_File(String ID, String type, String name, String path) {
        this.ID = new SimpleStringProperty(ID);
        this.type = new SimpleStringProperty(type);
        this.path = new SimpleStringProperty(path);
        this.name = new SimpleStringProperty(name);
    }

    public String getID() {
        return ID.get();
    }

    public String getType() {
        return type.get();
    }

    public String getName() {
        return name.get();
    }

    public String getPath() {
        return path.get();
    }

}
