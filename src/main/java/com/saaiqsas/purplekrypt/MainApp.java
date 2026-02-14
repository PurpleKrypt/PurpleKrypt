package com.saaiqsas.purplekrypt;



import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

import java.io.*;
import java.security.SecureRandom;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class MainApp extends Application {

    public static final String VERSION = "v1.0.0";
    /*
        +------------------------------------------------------------------------------------------------------------+
        |                                                                                                            |
        |     @@@@@@@@                                                                                               |
        |    @        @                                                                                              |
        |    @        @       @@@@@@@                           @           @     @                            @     |
        |    @        @       @      @                          @           @    @                             @     |
        |    @                @      @  @    @   @ @@ @@@@@@    @    @@@    @   @     @ @@  @     @  @@@@@@  @@@@@   |
        |     @@@@@@@@@@      @      @  @    @   @@   @     @   @  @     @  @@@@@     @@     @    @  @     @   @     |
        |   @@@@@@@@@   @     @@@@@@@   @    @   @    @     @   @  @@@@@@@  @   @     @       @  @   @     @   @     |
        |   @       @   @     @         @    @   @    @     @   @  @        @    @    @        @ @   @     @   @     |
        |   @    @@@@   @     @          @@@@    @    @@@@@@    @   @@@@@   @     @   @         @    @@@@@@    @     |
        |   @    @      @                             @                                        @     @               |
        |    @@@@@@@@@@                               @                                     @@@      @               |
        |                                                                                                            |
        +------------------------------------------------------------------------------------------------------------+


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


    private double x,y, x_log,y_log, x_wel,y_wel = 0;
    protected static boolean firstTime = false;

    protected static ComCon comcon;
    private static Stage logWin;
    protected static boolean LOG_WIN_SHOWN = false;

    protected static ArrayList<File> ALL_FILES_TO_PROCESS = new ArrayList<>();
    protected static ArrayList<File> ALL_DIR_TO_DELETE = new ArrayList<>();
    protected static int FILES_PROCESSED = -1;
    protected static int FILES_DELETED= -1;
    protected static long FILES_PROCESSING_START = 0;
    
    private static boolean ERROR_DURING_PROCESSING = false;
    private static boolean ERROR_DURING_DELETING = false;

    protected static int THREADS_PER_FILE = 4; // can be changed via UI
    private static long totalBytesProcessed = 0;

    protected static final int LOG_INTERVAL = 400; // milliseconds

    private static ExecutorService fileProcessingExecutor;


    public static void main(String[] args) {
        launch();
    }

    @Override
    public void start(Stage stage) throws IOException {
        Parent root = FXMLLoader.load(Objects.requireNonNull(getClass().getResource("main_layout.fxml")));
        Scene scene = new Scene(root, 800, 600);

        stage.setMinWidth(800);
        stage.setMinHeight(600);
        stage.setResizable(false);
        stage.setTitle("PurpleKrypt");
        stage.getIcons().add(new Image(Objects.requireNonNull(getClass().getResourceAsStream("PurpleKrypt_Icon_36p.png"))));
        stage.initStyle(StageStyle.UNDECORATED);

        root.setOnMousePressed(event -> {
            x = event.getSceneX();
            y = event.getSceneY();
        });

        root.setOnMouseDragged(event -> {
            stage.setX(event.getScreenX() - x);
            stage.setY(event.getScreenY() - y);
        });

        stage.setScene(scene);
        stage.show();

        Platform.runLater(() -> {
            try {
                setLogWin();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            initPkAadId();
            showWelcomeWin();

            // Test
            //try {SAS_PK.test();} catch (Exception e) {e.printStackTrace();}

        });

    }

    protected static void goToHelp(){
        openLink("https://purplekrypt.github.io/docs/graphical/graphical.html");
    }

    protected static void goToTerms(){
            openLink("https://purplekrypt.github.io/legal/terms.html");
    }

    private static void openLink(String URL){
        try {
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("linux") || os.contains("nix") || os.contains("nux")) { //Linux
                String[] commands = {
                        "xdg-open",
                        "firefox",
                        "google-chrome",
                        "sensible-browser",
                        "kde-open"
                };

                for (String command : commands) {
                        try {
                            Process process = new ProcessBuilder(command, URL).start();
                            return;
                        } catch (Exception ignored) {}
                }
                MainController.log("Go to ("+URL+")",false);

            } else if (os.contains("win")) { //Windows
                new ProcessBuilder("cmd", "/c", "start", URL).start();

            } else if (os.contains("mac")) { //MacOS
                new ProcessBuilder("open", URL).start();

            } else {
                MainController.log("Go to ("+URL+")",false);
               logToLogWin("[!] Cannot open link on this platform\n");
            }
        } catch (Exception e) {
            MainController.log("Go to ("+URL+")",false);
           logToLogWin("[!] An unexpected error has occurred while opening link:\n" + e + "\n");
        }
    }

    private void showWelcomeWin() {
        if (firstTime) {
            try {
                Stage welWin = new Stage();
                // Load the FXML for the welcome window
                Parent root = new FXMLLoader(Objects.requireNonNull(getClass().getResource("welcome_layout.fxml"))).load();
                Scene scene = new Scene(root, 430, 250);

                // Configure the Stage
                welWin.setMinWidth(430);
                welWin.setMinHeight(250);
                welWin.setResizable(false);
                welWin.setTitle("Welcome");
                welWin.getIcons().add(new Image(Objects.requireNonNull(getClass().getResourceAsStream("PurpleKrypt_Icon_36p.png"))));
                welWin.initStyle(StageStyle.UNDECORATED);

                // Set up dragging functionality
                root.setOnMousePressed(event -> {
                    x_wel = event.getSceneX();
                    y_wel = event.getSceneY();
                });

                root.setOnMouseDragged(event -> {
                    welWin.setX(event.getScreenX() - x_wel);
                    welWin.setY(event.getScreenY() - y_wel);
                });

                // Set the scene and show the window
                welWin.setScene(scene);
                welWin.show();
            } catch (Exception e) {
                logToLogWin("[!] Failed to load welcome window: " + e.getMessage());
            }
        }
    }


    private void setLogWin() throws IOException {
        logWin = new Stage();
        FXMLLoader loader = new FXMLLoader(Objects.requireNonNull(getClass().getResource("log_layout.fxml")));
        Parent root = loader.load();
        comcon = loader.getController();
        Scene scene = new Scene(root, 430, 600);

        logWin.setMinWidth(430);
        logWin.setMinHeight(600);
        logWin.setResizable(false);
        logWin.setTitle("Logs");
        logWin.getIcons().add(new Image(Objects.requireNonNull(getClass().getResourceAsStream("PurpleKrypt_Icon_36p.png"))));
        logWin.initStyle(StageStyle.UNDECORATED);

        root.setOnMousePressed(event -> {
            x_log = event.getSceneX();
            y_log = event.getSceneY();
        });

        root.setOnMouseDragged(event -> {
            logWin.setX(event.getScreenX() - x_log);
            logWin.setY(event.getScreenY() - y_log);
        });

        logWin.setScene(scene);
        logToLogWin("PurpleKrypt "+MainApp.VERSION+"  [API: "+SAS_PK.VERSION_IDENTIFIER+"]\nDeveloped by saaiqSAS, Licensed under GNU GPLv3\n(https://purplekrypt.github.io)\n\n");
    }

    protected static void showLogWin() {
        if (LOG_WIN_SHOWN) {
            logWin.hide();
        } else {
            logWin.show();
        }
        LOG_WIN_SHOWN = !LOG_WIN_SHOWN;

    }


    private static void initPkAadId() {
        try {
            File pk_aad_id = new File("pk_aad_id");
            if (!pk_aad_id.exists()) {
                MainController.PK_AAD_ID = SAS_PK.generatePkAadIdFile(pk_aad_id);
               logToLogWin("[*] pk_aad_id file generated. DO NOT DELETE THIS FILE\n");
                firstTime = true;
            } else {
                FileInputStream fileRead = new FileInputStream(pk_aad_id);
                MainController.PK_AAD_ID = fileRead.readNBytes(32);
               logToLogWin("[*] pk_aad_id file read\n");
            }
        } catch (Exception e) {
           logToLogWin("[!] An unexpected error has occurred while initializing PK AAD ID:\n"+ e + "\n");
        }
    }


    // ---------- Files Processing Methods ----------
    protected static void startProcessingFiles() {
        try {
            ERROR_DURING_PROCESSING = false;

            fileProcessingExecutor = Executors.newFixedThreadPool(MainController.THREADS);
            totalBytesProcessed = 0; // reset

            //startLogWinQue(); - log win que already started while scanning files onclick 'process'
            MainController.startSkipLog();

            if (MainController.FUNCTION_TYPE == 0) { // Encrypt

                notifyFileProcessed(false); // start UI notification

                    for (File eFile : ALL_FILES_TO_PROCESS) {
                        fileProcessingExecutor.submit(() -> MainApp.encryptFile(eFile));
                    }

            } else if (MainController.FUNCTION_TYPE == 1) { // Decrypt
                notifyFileProcessed(true); // start UI notification
                for (File eFile : ALL_FILES_TO_PROCESS) {
                    fileProcessingExecutor.submit(() -> MainApp.decryptFile(eFile));
                }
            }
        } catch (Exception e) {
            MainController.log("Failed to Process",true);
            logToLogWin("[!] Failed to start processing\n"+e+"\n");
        }
    }

    private static void encryptFile(File eFile) {
        try {
            SecureRandom rand = new SecureRandom();

            long fileSizeInBytes = eFile.length(); // get file size to display in logs
            totalBytesProcessed += fileSizeInBytes;
            String stringSize = (fileSizeInBytes < 1024) ? fileSizeInBytes + " Bytes" :
                    (fileSizeInBytes < 1048576) ? String.format("%.2f KB", fileSizeInBytes / 1024.0) :
                            (fileSizeInBytes < 1073741824) ? String.format("%.2f MB", fileSizeInBytes / 1048576.0) :
                                    String.format("%.2f GB", fileSizeInBytes / 1073741824.0);

            logToLogWinQue("[*] Encrypting " + eFile.getName() + " (" + stringSize + ") \n");

            // Setup Output File
            File outputFile;
            if (MainController.RANDOM_FILE_NAMES) {
                if (MainController.OUTPUT_METHOD == 2) { // random and replace
                    do {
                        outputFile = new File(eFile.getParentFile().getAbsolutePath() + "/" + SAS_PK.generateRandomString(rand.nextInt(10) + 5) + ".pk");
                    } while (outputFile.exists());

                } else { // random only
                    do {
                        outputFile = new File(MainController.OUTPUT_DIR + "/" + eFile.getParentFile().getAbsolutePath().replace(MainController.COMMON_PATH, "") + "/" + SAS_PK.generateRandomString(rand.nextInt(10) + 5) + ".pk");
                    } while (outputFile.exists());
                }

            } else {
                if (MainController.OUTPUT_METHOD == 2) { // replace only
                    outputFile = new File(eFile.getAbsolutePath() + ".pk");

                } else { // no random, no replace
                    outputFile = new File(MainController.OUTPUT_DIR + "/" + eFile.getAbsolutePath().replace(MainController.COMMON_PATH, "") + ".pk");

                }
            }
            outputFile.getParentFile().mkdirs();

            int outcome;
            // Process
            outcome = SAS_PK.encryptFile(SAS_PK.KEY, SAS_PK.PASSWORD, eFile, outputFile, MainController.PK_AAD_ID, MainController.USE_PK_AAD_ID);

            if (outcome == 1) {
                logToLogWinQue("[!] Failed to encrypt " + eFile.getName() + " (" + stringSize + ") \n");
                ERROR_DURING_PROCESSING = true;
            }

        } catch (Exception e) {
            ERROR_DURING_PROCESSING = true;
            logToLogWin("[!] "+eFile.getPath()+" Could Not Be Encrypted Correctly\n"+e+"\n");
        }
        notifyFileProcessed(false);
    }


    private static void decryptFile(File eFile) {
        try {
            long fileSizeInBytes = eFile.length(); // get file size to display in logs
            totalBytesProcessed += fileSizeInBytes;
            String stringSize = (fileSizeInBytes < 1024) ? fileSizeInBytes + " Bytes" :
                    (fileSizeInBytes < 1048576) ? String.format("%.2f KB", fileSizeInBytes / 1024.0) :
                            (fileSizeInBytes < 1073741824) ? String.format("%.2f MB", fileSizeInBytes / 1048576.0) :
                                    String.format("%.2f GB", fileSizeInBytes / 1073741824.0);

            logToLogWinQue("[*] Decrypting "+eFile.getName()+" ("+stringSize+") \n");

            // Setup Output File
            File outputDir;
            if (MainController.OUTPUT_METHOD == 2) {
                outputDir = new File(eFile.getParentFile().getAbsolutePath() + "/");
            } else {
                outputDir = new File(MainController.OUTPUT_DIR + "/" + eFile.getParentFile().getAbsolutePath().replace(MainController.COMMON_PATH, "") + "/");
            }
            outputDir.mkdirs();

            int outcome;
            // Process
            outcome = SAS_PK.decryptFile(SAS_PK.KEY, SAS_PK.PASSWORD, eFile, outputDir, MainController.PK_AAD_ID);

            switch (outcome) {
                case 1 -> {
                    logToLogWinQue("[!] Failed to decrypt " + eFile.getName() + " (" + stringSize + ") - Wrong Keyfile/Password or Corrupted. \n");
                    ERROR_DURING_PROCESSING = true;
                }
                case 2 -> {
                    logToLogWinQue("[!] Failed to decrypt " + eFile.getName() + " (" + stringSize + ") - File was encrypted with an older version of PurpleKrypt.\n");
                    ERROR_DURING_PROCESSING = true;
                }
                case 3 -> {
                    logToLogWinQue("[!] Failed to decrypt " + eFile.getName() + " (" + stringSize + ") - File was encrypted with a newer version of PurpleKrypt.\n");
                    ERROR_DURING_PROCESSING = true;
                }
                case 4 -> {
                    logToLogWinQue("[!] Failed to decrypt " + eFile.getName() + " (" + stringSize + ") - Corrupted, some data is missing.\n");
                    ERROR_DURING_PROCESSING = true;
                }
            }


        } catch (Exception e) {
            ERROR_DURING_PROCESSING = true;
            logToLogWin("[!] "+eFile.getPath()+" Could Not Be Decrypted Correctly\n"+"[!]"+e+"\n");

        }
        notifyFileProcessed(true);
    }

    private static synchronized void notifyFileProcessed(boolean isDecrypt) {
        FILES_PROCESSED++;
        if (FILES_PROCESSED < ALL_FILES_TO_PROCESS.size()) {
            if (!isDecrypt) {
                MainController.logToSkipLog("Encrypting...(" + FILES_PROCESSED + "/" + ALL_FILES_TO_PROCESS.size() + " files completed)", false);
            } else {
                MainController.logToSkipLog("Decrypting...(" + FILES_PROCESSED + "/" + ALL_FILES_TO_PROCESS.size() + " files completed)", false);
            }


        } else {
            if (MainController.OUTPUT_METHOD != 0 && !ERROR_DURING_PROCESSING) {
                deleteInputFiles();

            } else {
                // Once all files are processed and no need to delete input files
                double duration = (double) (System.currentTimeMillis() - FILES_PROCESSING_START) / 1000.0;
                String totalSizeProcessed = (totalBytesProcessed < 1024) ? totalBytesProcessed + " Bytes" :
                        (totalBytesProcessed < 1048576) ? String.format("%.2f KB", totalBytesProcessed / 1024.0) :
                                (totalBytesProcessed < 1073741824) ? String.format("%.2f MB", totalBytesProcessed / 1048576.0) :
                                        String.format("%.2f GB", totalBytesProcessed / 1073741824.0);

                if (ERROR_DURING_PROCESSING) {
                    MainController.logToSkipLog("Finished (in " + duration + "secs), with Errors", false);
                    logToLogWinQue("[!] Finished ("+totalSizeProcessed+" in " + duration + "secs), with Errors\n");
                } else {
                    MainController.logToSkipLog("Finished (in " + duration + "secs)", false);
                    logToLogWinQue("[+] Finished ("+totalSizeProcessed+" in " + duration + "secs)\n");
                }

                fileProcessingExecutor.shutdown();
                stopLogWinQue();
                MainController.stopSkipLog();
                MainController.enable_confirm_process_button();
            }
        }

    }


    protected static void deleteInputFiles() {
        try {
            FILES_DELETED= -1;
            notifyFileDeleted(); // start UI notification

            for (File eFile : ALL_FILES_TO_PROCESS) {
                fileProcessingExecutor.submit(() -> deleteFile(eFile));
            }


        } catch (Exception e) {
            MainController.log("Failed to delete files",true);
            logToLogWin("[!] Failed to delete files\n"+e+"\n");
        }
    }

    private static void deleteFile(File eFile ) {
        boolean del = SAS_PK.deleteFileSecurely(eFile);
        if (del) {
            logToLogWinQue("[*] Deleted " + eFile.getName() + "\n");
        } else {
            logToLogWinQue("[!] Failed to delete " + eFile.getName() + "\n");
            ERROR_DURING_DELETING = true;
        }
        notifyFileDeleted();
    }

    private static synchronized void notifyFileDeleted() {
        FILES_DELETED++;

        if (FILES_DELETED < ALL_FILES_TO_PROCESS.size()) {
            MainController.logToSkipLog("Deleting Input Files...(" + FILES_DELETED + "/" + ALL_FILES_TO_PROCESS.size() + " files attempted)", false);

        } else {
            // Once all files are processed

            // delete directories
            boolean ERROR_DELETING_DIR = false;
            if (MainController.OUTPUT_METHOD != 2) {
                if (!ALL_DIR_TO_DELETE.isEmpty()) {
                    MainController.logToSkipLog("Deleting Directories...(", false);
                    for (int i = ALL_DIR_TO_DELETE.size() - 1; i >= 0; i--) {
                        File eDir = ALL_DIR_TO_DELETE.get(i);
                        boolean deletedDir = eDir.delete(); // normal delete
                        if (!deletedDir) {
                            logToLogWinQue("[!] Failed to delete directory " + eDir.getName() + "\n");
                            ERROR_DELETING_DIR = true;
                        }
                    }
                }
            }

            double duration = (double) (System.currentTimeMillis() - FILES_PROCESSING_START) / 1000.0;

            String totalSizeProcessed = (totalBytesProcessed < 1024) ? totalBytesProcessed + " Bytes" :
                    (totalBytesProcessed < 1048576) ? String.format("%.2f KB", totalBytesProcessed / 1024.0) :
                            (totalBytesProcessed < 1073741824) ? String.format("%.2f MB", totalBytesProcessed / 1048576.0) :
                                    String.format("%.2f GB", totalBytesProcessed / 1073741824.0);

            if (ERROR_DURING_PROCESSING || ERROR_DURING_DELETING || ERROR_DELETING_DIR) {
                MainController.logToSkipLog("Finished (in " + duration + "secs), with Errors", false);
                logToLogWinQue("[!] Finished ("+totalSizeProcessed+" in " + duration + "secs), with Errors\n");
            } else {
                MainController.logToSkipLog("Finished (in " + duration + "secs)", false);
                logToLogWinQue("[+] Finished ("+totalSizeProcessed+" in " + duration + "secs)\n");
            }

            fileProcessingExecutor.shutdown();
            stopLogWinQue();
            MainController.stopSkipLog();
            MainController.enable_confirm_process_button();
        }

    }


    // ---------- Logging----------
    private static ScheduledExecutorService logWinQueSchedule;
    private static final Queue<String> logWinQue = new LinkedList<>();
    
    protected static void startLogWinQue() {
        logWinQueSchedule = Executors.newScheduledThreadPool(1);
        logWinQueSchedule.scheduleAtFixedRate(() -> {
            StringBuilder batch = new StringBuilder();
            synchronized (logWinQue) {
                while (!logWinQue.isEmpty()) {
                    batch.append(logWinQue.poll());
                }
            }
            
            if (!batch.isEmpty()) {
                Platform.runLater(() -> comcon.log_display.appendText(batch.toString()));
            }
        },0,LOG_INTERVAL, TimeUnit.MILLISECONDS);
    }

    protected static void stopLogWinQue() {
        StringBuilder batch = new StringBuilder();
        synchronized (logWinQue) {
            while (!logWinQue.isEmpty()) {
                batch.append(logWinQue.poll());
            }
        }

        if (!batch.isEmpty()) {
            Platform.runLater(() -> comcon.log_display.appendText(batch.toString()));
        }
        logWinQueSchedule.shutdown();
    }
    
    protected static void logToLogWinQue(String log) {
        synchronized (logWinQue) {
            logWinQue.add(log);
        }
    }
    
    protected static synchronized void logToLogWin(String log) {
        Platform.runLater(() -> comcon.log_display.appendText(log));
    } 
    
    // ---------- Additional Support Methods ----------
    private static boolean isCommandAvailableLinux(String command) {
        try {
            Process process = new ProcessBuilder("which", command).start();
            process.waitFor();
            return process.exitValue() == 0;  // If exit code is 0, command is found
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }

    public static boolean deleteFileRecursively(File file) {
        //NON SECURE
        if (file.isDirectory()) {
            for (File subFile : Objects.requireNonNull(file.listFiles())) {
                deleteFileRecursively(subFile);
            }
        }
        return file.delete();
    }

}