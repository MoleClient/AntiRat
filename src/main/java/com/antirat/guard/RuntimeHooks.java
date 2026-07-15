package com.antirat.guard;

import com.antirat.AntiRatRuntime;
import com.antirat.model.RiskLevel;
import com.antirat.model.ThreatEvent;
import com.antirat.model.ThreatType;
import com.antirat.scan.Capability;
import com.antirat.scan.ModIdentity;
import com.antirat.scan.ModIndex;
import com.antirat.scan.ScanRegistry;
import com.antirat.scan.ScanResult;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.invoke.VarHandle;
import java.lang.management.RuntimeMXBean;
import java.awt.Desktop;
import java.net.CookieHandler;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.http.WebSocket;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.channels.FileChannel;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.DatagramChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.SocketChannel;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.CopyOption;
import java.nio.file.spi.FileSystemProvider;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.ExecutorService;
import java.util.stream.Stream;
import javax.net.SocketFactory;

/**
 * Targets for Java-agent call-site rewriting. These methods enforce before delegating to the JDK API.
 * They intentionally never capture credential values, request bodies, file contents, or command arguments.
 */
public final class RuntimeHooks {
    private static final long REPORT_SUPPRESS_MS = 15_000L;
    private static final Map<String, Long> LAST_REPORT = new ConcurrentHashMap<>();
    private static final StackWalker REFLECTION_CALLER_WALKER =
            StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);

    private RuntimeHooks() {
    }

    public static InputStream filesNewInputStream(Path path, OpenOption... options) throws IOException {
        checkSensitiveRead(path);
        return Files.newInputStream(path, options);
    }

    public static byte[] filesReadAllBytes(Path path) throws IOException {
        if (Boolean.getBoolean("antirat.runtime.probe")) {
            System.setProperty("antirat.runtime.probe.hit", "true");
        }
        checkSensitiveRead(path);
        return Files.readAllBytes(path);
    }

    public static String filesReadString(Path path) throws IOException {
        checkSensitiveRead(path);
        return Files.readString(path);
    }

    public static String filesReadString(Path path, Charset charset) throws IOException {
        checkSensitiveRead(path);
        return Files.readString(path, charset);
    }

    public static BufferedReader filesNewBufferedReader(Path path) throws IOException {
        checkSensitiveRead(path);
        return Files.newBufferedReader(path);
    }

    public static BufferedReader filesNewBufferedReader(Path path, Charset charset) throws IOException {
        checkSensitiveRead(path);
        return Files.newBufferedReader(path, charset);
    }

    public static Stream<String> filesLines(Path path) throws IOException {
        checkSensitiveRead(path);
        return Files.lines(path);
    }

    public static Stream<String> filesLines(Path path, Charset charset) throws IOException {
        checkSensitiveRead(path);
        return Files.lines(path, charset);
    }

    public static List<String> filesReadAllLines(Path path) throws IOException {
        checkSensitiveRead(path);
        return Files.readAllLines(path);
    }

    public static List<String> filesReadAllLines(Path path, Charset charset) throws IOException {
        checkSensitiveRead(path);
        return Files.readAllLines(path, charset);
    }

    public static long filesCopy(Path source, OutputStream target) throws IOException {
        checkSensitiveRead(source);
        return Files.copy(source, target);
    }

    public static Path filesCopy(Path source, Path target, CopyOption... options) throws IOException {
        checkSensitiveRead(source);
        return Files.copy(source, target, options);
    }

    public static long filesMismatch(Path first, Path second) throws IOException {
        checkSensitiveRead(first);
        checkSensitiveRead(second);
        return Files.mismatch(first, second);
    }

    public static Path filesCreateLink(Path link, Path existing) throws IOException {
        checkSensitiveRead(existing);
        return Files.createLink(link, existing);
    }

    public static Path filesCreateSymbolicLink(Path link, Path target, FileAttribute<?>... attributes)
            throws IOException {
        Path resolved = target.isAbsolute() ? target
                : (link.toAbsolutePath().getParent() == null ? target : link.toAbsolutePath().getParent().resolve(target));
        checkSensitiveRead(resolved.normalize());
        return Files.createSymbolicLink(link, target, attributes);
    }

    public static Path filesMove(Path source, Path target, CopyOption... options) throws IOException {
        checkSensitiveRead(source);
        return Files.move(source, target, options);
    }

    public static InputStream providerNewInputStream(
            FileSystemProvider provider, Path path, OpenOption... options
    ) throws IOException {
        checkSensitiveRead(path);
        return provider.newInputStream(path, options);
    }

    public static SeekableByteChannel providerNewByteChannel(
            FileSystemProvider provider, Path path, Set<? extends OpenOption> options,
            FileAttribute<?>... attributes
    ) throws IOException {
        checkSensitiveRead(path);
        return provider.newByteChannel(path, options, attributes);
    }

    public static FileChannel providerNewFileChannel(
            FileSystemProvider provider, Path path, Set<? extends OpenOption> options,
            FileAttribute<?>... attributes
    ) throws IOException {
        checkSensitiveRead(path);
        return provider.newFileChannel(path, options, attributes);
    }

    public static SeekableByteChannel filesNewByteChannel(Path path, OpenOption... options) throws IOException {
        checkSensitiveRead(path);
        return Files.newByteChannel(path, options);
    }

    public static SeekableByteChannel filesNewByteChannel(
            Path path, Set<? extends OpenOption> options, FileAttribute<?>... attributes
    ) throws IOException {
        checkSensitiveRead(path);
        return Files.newByteChannel(path, options, attributes);
    }

    public static FileChannel fileChannelOpen(Path path, OpenOption... options) throws IOException {
        checkSensitiveRead(path);
        return FileChannel.open(path, options);
    }

    public static FileChannel fileChannelOpen(
            Path path, Set<? extends OpenOption> options, FileAttribute<?>... attributes
    ) throws IOException {
        checkSensitiveRead(path);
        return FileChannel.open(path, options, attributes);
    }

    public static AsynchronousFileChannel asynchronousFileChannelOpen(
            Path path, OpenOption... options
    ) throws IOException {
        checkSensitiveRead(path);
        return AsynchronousFileChannel.open(path, options);
    }

    public static AsynchronousFileChannel asynchronousFileChannelOpen(
            Path path, Set<? extends OpenOption> options, ExecutorService executor,
            FileAttribute<?>... attributes
    ) throws IOException {
        checkSensitiveRead(path);
        return AsynchronousFileChannel.open(path, options, executor, attributes);
    }

    public static AsynchronousFileChannel providerNewAsynchronousFileChannel(
            FileSystemProvider provider, Path path, Set<? extends OpenOption> options,
            ExecutorService executor, FileAttribute<?>... attributes
    ) throws IOException {
        checkSensitiveRead(path);
        return provider.newAsynchronousFileChannel(path, options, executor, attributes);
    }

    public static String guardFileRead(String path) {
        if (path != null) checkSensitiveRead(Path.of(path));
        return path;
    }

    public static File guardFileRead(File file) {
        if (file != null) checkSensitiveRead(file.toPath());
        return file;
    }

    public static Path guardFileRead(Path path) {
        if (path != null) checkSensitiveRead(path);
        return path;
    }

    public static java.io.FileInputStream fileInputStreamCreate(String path) throws IOException {
        guardFileRead(path);
        return new java.io.FileInputStream(path);
    }

    public static java.io.FileInputStream fileInputStreamCreate(File file) throws IOException {
        guardFileRead(file);
        return new java.io.FileInputStream(file);
    }

    public static java.io.FileReader fileReaderCreate(String path) throws IOException {
        guardFileRead(path);
        return new java.io.FileReader(path);
    }

    public static java.io.FileReader fileReaderCreate(File file) throws IOException {
        guardFileRead(file);
        return new java.io.FileReader(file);
    }

    public static java.io.FileReader fileReaderCreate(String path, Charset charset) throws IOException {
        guardFileRead(path);
        return new java.io.FileReader(path, charset);
    }

    public static java.io.FileReader fileReaderCreate(File file, Charset charset) throws IOException {
        guardFileRead(file);
        return new java.io.FileReader(file, charset);
    }

    public static java.io.RandomAccessFile randomAccessFileCreate(String path, String mode) throws IOException {
        guardFileRead(path);
        return new java.io.RandomAccessFile(path, mode);
    }

    public static java.io.RandomAccessFile randomAccessFileCreate(File file, String mode) throws IOException {
        guardFileRead(file);
        return new java.io.RandomAccessFile(file, mode);
    }

    public static java.util.Scanner scannerCreate(File file) throws IOException {
        guardFileRead(file);
        return new java.util.Scanner(file);
    }

    public static java.util.Scanner scannerCreate(File file, String charset) throws IOException {
        guardFileRead(file);
        return new java.util.Scanner(file, charset);
    }

    public static java.util.Scanner scannerCreate(File file, Charset charset) throws IOException {
        guardFileRead(file);
        return new java.util.Scanner(file, charset);
    }

    public static java.util.Scanner scannerCreate(Path path) throws IOException {
        guardFileRead(path);
        return new java.util.Scanner(path);
    }

    public static java.util.Scanner scannerCreate(Path path, String charset) throws IOException {
        guardFileRead(path);
        return new java.util.Scanner(path, charset);
    }

    public static java.util.Scanner scannerCreate(Path path, Charset charset) throws IOException {
        guardFileRead(path);
        return new java.util.Scanner(path, charset);
    }

    public static Socket socketCreate(String host, int port) throws IOException {
        checkHostPort(host, port);
        return new Socket(host, port);
    }

    public static Socket socketCreate(InetAddress host, int port) throws IOException {
        checkHostPort(host, port);
        return new Socket(host, port);
    }

    public static Socket socketCreate(
            String host, int port, InetAddress localAddress, int localPort
    ) throws IOException {
        checkHostPort(host, port);
        return new Socket(host, port, localAddress, localPort);
    }

    public static Socket socketCreate(
            InetAddress host, int port, InetAddress localAddress, int localPort
    ) throws IOException {
        checkHostPort(host, port);
        return new Socket(host, port, localAddress, localPort);
    }

    public static Connection driverManagerGetConnection(String url) throws SQLException {
        checkJdbcUrl(url);
        return DriverManager.getConnection(url);
    }

    public static Connection driverManagerGetConnection(String url, Properties properties) throws SQLException {
        checkJdbcUrl(url);
        return DriverManager.getConnection(url, properties);
    }

    public static Connection driverManagerGetConnection(String url, String user, String password)
            throws SQLException {
        checkJdbcUrl(url);
        return DriverManager.getConnection(url, user, password);
    }

    public static URLConnection urlOpenConnection(URL url) throws IOException {
        checkUri(toUri(url));
        return url.openConnection();
    }

    public static URLConnection urlOpenConnection(URL url, Proxy proxy) throws IOException {
        checkUri(toUri(url));
        return url.openConnection(proxy);
    }

    public static InputStream urlOpenStream(URL url) throws IOException {
        checkUri(toUri(url));
        return url.openStream();
    }

    public static Object urlGetContent(URL url) throws IOException {
        checkUri(toUri(url));
        return url.getContent();
    }

    public static Object urlGetContent(URL url, Class<?>[] types) throws IOException {
        checkUri(toUri(url));
        return url.getContent(types);
    }

    public static <T> HttpResponse<T> httpSend(
            HttpClient client, HttpRequest request, HttpResponse.BodyHandler<T> handler
    ) throws IOException, InterruptedException {
        checkUri(request.uri());
        return client.send(request, handler);
    }

    public static <T> CompletableFuture<HttpResponse<T>> httpSendAsync(
            HttpClient client, HttpRequest request, HttpResponse.BodyHandler<T> handler
    ) {
        checkUri(request.uri());
        return client.sendAsync(request, handler);
    }

    public static CompletableFuture<WebSocket> webSocketBuildAsync(
            WebSocket.Builder builder, URI uri, WebSocket.Listener listener
    ) {
        checkUri(uri);
        return builder.buildAsync(uri, listener);
    }

    public static <T> CompletableFuture<HttpResponse<T>> httpSendAsync(
            HttpClient client,
            HttpRequest request,
            HttpResponse.BodyHandler<T> handler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler
    ) {
        checkUri(request.uri());
        return client.sendAsync(request, handler, pushPromiseHandler);
    }

    public static void socketConnect(Socket socket, SocketAddress address) throws IOException {
        checkSocketAddress(address);
        socket.connect(address);
    }

    public static void socketConnect(Socket socket, SocketAddress address, int timeout) throws IOException {
        checkSocketAddress(address);
        socket.connect(address, timeout);
    }

    public static boolean socketChannelConnect(SocketChannel channel, SocketAddress address) throws IOException {
        checkSocketAddress(address);
        return channel.connect(address);
    }

    public static SocketChannel socketChannelOpen(SocketAddress address) throws IOException {
        checkSocketAddress(address);
        return SocketChannel.open(address);
    }

    public static Future<Void> asynchronousSocketConnect(AsynchronousSocketChannel channel, SocketAddress address) {
        checkSocketAddress(address);
        return channel.connect(address);
    }

    public static <A> void asynchronousSocketConnect(
            AsynchronousSocketChannel channel, SocketAddress address, A attachment,
            CompletionHandler<Void, ? super A> handler
    ) {
        checkSocketAddress(address);
        channel.connect(address, attachment, handler);
    }

    public static void datagramConnect(DatagramSocket socket, SocketAddress address) throws java.net.SocketException {
        checkSocketAddress(address);
        socket.connect(address);
    }

    public static void datagramConnect(DatagramSocket socket, InetAddress address, int port) {
        checkHostPort(address == null ? "" : address.getHostAddress(), port);
        socket.connect(address, port);
    }

    public static void datagramSend(DatagramSocket socket, DatagramPacket packet) throws IOException {
        if (packet != null) checkHostPort(packet.getAddress(), packet.getPort());
        socket.send(packet);
    }

    public static int datagramChannelSend(DatagramChannel channel, ByteBuffer source, SocketAddress target)
            throws IOException {
        checkSocketAddress(target);
        return channel.send(source, target);
    }

    public static DatagramChannel datagramChannelConnect(DatagramChannel channel, SocketAddress target)
            throws IOException {
        checkSocketAddress(target);
        return channel.connect(target);
    }

    public static Socket socketFactoryCreateSocket(SocketFactory factory, String host, int port) throws IOException {
        checkHostPort(host, port);
        return factory.createSocket(host, port);
    }

    public static Socket socketFactoryCreateSocket(SocketFactory factory, InetAddress host, int port) throws IOException {
        checkHostPort(host, port);
        return factory.createSocket(host, port);
    }

    public static Socket socketFactoryCreateSocket(
            SocketFactory factory, String host, int port, InetAddress localAddress, int localPort
    ) throws IOException {
        checkHostPort(host, port);
        return factory.createSocket(host, port, localAddress, localPort);
    }

    public static Socket socketFactoryCreateSocket(
            SocketFactory factory, InetAddress host, int port, InetAddress localAddress, int localPort
    ) throws IOException {
        checkHostPort(host, port);
        return factory.createSocket(host, port, localAddress, localPort);
    }

    public static InetAddress inetAddressGetByName(String host) throws java.net.UnknownHostException {
        checkHostPort(host, 53);
        return InetAddress.getByName(host);
    }

    public static InetAddress[] inetAddressGetAllByName(String host) throws java.net.UnknownHostException {
        checkHostPort(host, 53);
        return InetAddress.getAllByName(host);
    }

    public static void desktopBrowse(Desktop desktop, URI uri) throws IOException {
        checkUri(uri);
        desktop.browse(uri);
    }

    public static void proxySelectorSetDefault(ProxySelector selector) {
        ProxySelector.setDefault(selector instanceof GuardedProxySelector ? selector : new GuardedProxySelector(selector));
    }

    public static void cookieHandlerSetDefault(CookieHandler handler) {
        CookieHandler.setDefault(handler instanceof GuardedCookieHandler ? handler : new GuardedCookieHandler(handler));
    }

    public static String systemGetenv(String name) {
        if (!isSensitiveSecretName(name)) return System.getenv(name);
        reportMetadataProtection("Blocked sensitive environment-variable access", "environment variable", true);
        return null;
    }

    public static Map<String, String> systemGetenv() {
        Map<String, String> filtered = new HashMap<>();
        boolean removed = false;
        for (Map.Entry<String, String> entry : System.getenv().entrySet()) {
            if (isSensitiveSecretName(entry.getKey())) removed = true;
            else filtered.put(entry.getKey(), entry.getValue());
        }
        if (removed) reportMetadataProtection("Filtered sensitive environment variables", "environment", false);
        return Map.copyOf(filtered);
    }

    public static String systemGetProperty(String name) {
        if (isCommandProperty(name)) return redactCommandLine(System.getProperty(name));
        if (!isSensitiveSecretName(name)) return System.getProperty(name);
        reportMetadataProtection("Blocked sensitive system-property access", "system property", true);
        return null;
    }

    public static String systemGetProperty(String name, String fallback) {
        String value = systemGetProperty(name);
        return value == null ? fallback : value;
    }

    public static Properties systemGetProperties() {
        Properties filtered = new Properties();
        boolean removed = false;
        for (Map.Entry<Object, Object> entry : System.getProperties().entrySet()) {
            String key = String.valueOf(entry.getKey());
            if (isCommandProperty(key)) filtered.setProperty(key, redactCommandLine(String.valueOf(entry.getValue())));
            else if (isSensitiveSecretName(key)) removed = true;
            else filtered.put(entry.getKey(), entry.getValue());
        }
        if (removed) reportMetadataProtection("Filtered sensitive system properties", "system properties", false);
        return filtered;
    }

    public static Optional<String[]> processInfoArguments(ProcessHandle.Info info) {
        Optional<String[]> arguments = info.arguments();
        if (arguments.isEmpty()) return arguments;
        String[] original = arguments.get();
        String[] redacted = redactArguments(original);
        if (!java.util.Arrays.equals(original, redacted)) {
            reportMetadataProtection("Redacted credential-bearing launch arguments", "process arguments", false);
        }
        return Optional.of(redacted);
    }

    public static Optional<String> processInfoCommandLine(ProcessHandle.Info info) {
        Optional<String> commandLine = info.commandLine();
        if (commandLine.isEmpty()) return commandLine;
        String redacted = redactCommandLine(commandLine.get());
        if (!redacted.equals(commandLine.get())) {
            reportMetadataProtection("Redacted credential-bearing command line", "process command line", false);
        }
        return Optional.of(redacted);
    }

    public static Map<String, String> processBuilderEnvironment(ProcessBuilder builder) {
        Map<String, String> environment = builder.environment();
        boolean removed = environment.entrySet().removeIf(entry -> isSensitiveSecretName(entry.getKey()));
        if (removed) {
            reportMetadataProtection("Filtered sensitive process-builder environment variables",
                    "process environment", false);
        }
        return environment;
    }

    public static List<String> runtimeMxBeanGetInputArguments(RuntimeMXBean bean) {
        List<String> arguments = bean.getInputArguments();
        String[] original = arguments.toArray(String[]::new);
        String[] redacted = redactArguments(original);
        if (!java.util.Arrays.equals(original, redacted)) {
            reportMetadataProtection("Redacted credential-bearing JVM arguments", "JVM arguments", false);
        }
        return List.copyOf(java.util.Arrays.asList(redacted));
    }

    public static Map<String, String> runtimeMxBeanGetSystemProperties(RuntimeMXBean bean) {
        Map<String, String> filtered = new HashMap<>();
        boolean removed = false;
        for (Map.Entry<String, String> entry : bean.getSystemProperties().entrySet()) {
            if (isCommandProperty(entry.getKey())) {
                filtered.put(entry.getKey(), redactCommandLine(entry.getValue()));
            } else if (isSensitiveSecretName(entry.getKey())) {
                removed = true;
            } else {
                filtered.put(entry.getKey(), entry.getValue());
            }
        }
        if (removed) {
            reportMetadataProtection("Filtered sensitive runtime system properties", "runtime properties", false);
        }
        return Map.copyOf(filtered);
    }

    public static void checkHostPort(String host, int port) {
        checkUri(socketUri(host, port));
    }

    public static void checkHostPort(InetAddress address, int port) {
        checkHostPort(address == null ? "" : address.getHostAddress(), port);
    }

    public static Process processStart(ProcessBuilder builder) throws IOException {
        checkProcess(builder == null || builder.command().isEmpty() ? "" : builder.command().getFirst());
        return builder.start();
    }

    public static List<Process> processStartPipeline(List<ProcessBuilder> builders) throws IOException {
        if (builders == null) throw new NullPointerException("builders");
        for (ProcessBuilder builder : builders) {
            checkProcess(builder == null || builder.command().isEmpty() ? "" : builder.command().getFirst());
        }
        return ProcessBuilder.startPipeline(builders);
    }

    public static Process runtimeExec(Runtime runtime, String command) throws IOException {
        checkProcess(command);
        return runtime.exec(command);
    }

    public static Process runtimeExec(Runtime runtime, String[] command) throws IOException {
        checkProcess(first(command));
        return runtime.exec(command);
    }

    public static Process runtimeExec(Runtime runtime, String command, String[] environment) throws IOException {
        checkProcess(command);
        return runtime.exec(command, environment);
    }

    public static Process runtimeExec(Runtime runtime, String[] command, String[] environment) throws IOException {
        checkProcess(first(command));
        return runtime.exec(command, environment);
    }

    public static Process runtimeExec(Runtime runtime, String command, String[] environment, File directory) throws IOException {
        checkProcess(command);
        return runtime.exec(command, environment, directory);
    }

    public static Process runtimeExec(Runtime runtime, String[] command, String[] environment, File directory) throws IOException {
        checkProcess(first(command));
        return runtime.exec(command, environment, directory);
    }

    public static void systemLoad(String path) {
        checkNativeLoad(path);
        System.load(path);
    }

    public static void systemLoadLibrary(String library) {
        checkNativeLoad(library);
        System.loadLibrary(library);
    }

    public static void runtimeLoad(Runtime runtime, String path) {
        checkNativeLoad(path);
        runtime.load(path);
    }

    public static void runtimeLoadLibrary(Runtime runtime, String library) {
        checkNativeLoad(library);
        runtime.loadLibrary(library);
    }

    public static Object reflectiveFieldGet(java.lang.reflect.Field field, Object target) throws IllegalAccessException {
        guardAntiRatReflection(field.getDeclaringClass(), "private field read");
        if (isSessionTokenField(field.getDeclaringClass().getName(), field.getName(), field.getType())) {
            blockDirectSessionAccess("Reflective access to Minecraft's session-token field was denied");
            return "";
        }
        if (isCredentialObjectField(field.getDeclaringClass().getName(), field.getName(), field.getType())) {
            blockDirectSessionAccess("Reflective access to an authenticated Minecraft service was denied");
            return null;
        }
        Class<?> caller = originalReflectionCaller();
        return withLanguageAccess(field, target, caller, () -> field.get(target));
    }

    public static boolean reflectiveFieldGetBoolean(Field field, Object target) throws IllegalAccessException {
        guardAntiRatReflection(field.getDeclaringClass(), "private primitive field read");
        Class<?> caller = originalReflectionCaller();
        return withLanguageAccess(field, target, caller, () -> field.getBoolean(target));
    }

    public static byte reflectiveFieldGetByte(Field field, Object target) throws IllegalAccessException {
        guardAntiRatReflection(field.getDeclaringClass(), "private primitive field read");
        Class<?> caller = originalReflectionCaller();
        return withLanguageAccess(field, target, caller, () -> field.getByte(target));
    }

    public static char reflectiveFieldGetChar(Field field, Object target) throws IllegalAccessException {
        guardAntiRatReflection(field.getDeclaringClass(), "private primitive field read");
        Class<?> caller = originalReflectionCaller();
        return withLanguageAccess(field, target, caller, () -> field.getChar(target));
    }

    public static short reflectiveFieldGetShort(Field field, Object target) throws IllegalAccessException {
        guardAntiRatReflection(field.getDeclaringClass(), "private primitive field read");
        Class<?> caller = originalReflectionCaller();
        return withLanguageAccess(field, target, caller, () -> field.getShort(target));
    }

    public static int reflectiveFieldGetInt(Field field, Object target) throws IllegalAccessException {
        guardAntiRatReflection(field.getDeclaringClass(), "private primitive field read");
        Class<?> caller = originalReflectionCaller();
        return withLanguageAccess(field, target, caller, () -> field.getInt(target));
    }

    public static long reflectiveFieldGetLong(Field field, Object target) throws IllegalAccessException {
        guardAntiRatReflection(field.getDeclaringClass(), "private primitive field read");
        Class<?> caller = originalReflectionCaller();
        return withLanguageAccess(field, target, caller, () -> field.getLong(target));
    }

    public static float reflectiveFieldGetFloat(Field field, Object target) throws IllegalAccessException {
        guardAntiRatReflection(field.getDeclaringClass(), "private primitive field read");
        Class<?> caller = originalReflectionCaller();
        return withLanguageAccess(field, target, caller, () -> field.getFloat(target));
    }

    public static double reflectiveFieldGetDouble(Field field, Object target) throws IllegalAccessException {
        guardAntiRatReflection(field.getDeclaringClass(), "private primitive field read");
        Class<?> caller = originalReflectionCaller();
        return withLanguageAccess(field, target, caller, () -> field.getDouble(target));
    }

    public static void reflectiveFieldSet(java.lang.reflect.Field field, Object target, Object value)
            throws IllegalAccessException {
        guardSensitiveFieldMutation(field);
        Class<?> caller = originalReflectionCaller();
        withLanguageAccess(field, target, caller, () -> {
            field.set(target, value);
            return null;
        });
    }

    public static void reflectiveFieldSetBoolean(java.lang.reflect.Field field, Object target, boolean value)
            throws IllegalAccessException {
        guardSensitiveFieldMutation(field);
        Class<?> caller = originalReflectionCaller();
        withLanguageAccess(field, target, caller, () -> {
            field.setBoolean(target, value);
            return null;
        });
    }

    public static void reflectiveFieldSetByte(java.lang.reflect.Field field, Object target, byte value)
            throws IllegalAccessException {
        guardSensitiveFieldMutation(field);
        Class<?> caller = originalReflectionCaller();
        withLanguageAccess(field, target, caller, () -> {
            field.setByte(target, value);
            return null;
        });
    }

    public static void reflectiveFieldSetChar(java.lang.reflect.Field field, Object target, char value)
            throws IllegalAccessException {
        guardSensitiveFieldMutation(field);
        Class<?> caller = originalReflectionCaller();
        withLanguageAccess(field, target, caller, () -> {
            field.setChar(target, value);
            return null;
        });
    }

    public static void reflectiveFieldSetShort(java.lang.reflect.Field field, Object target, short value)
            throws IllegalAccessException {
        guardSensitiveFieldMutation(field);
        Class<?> caller = originalReflectionCaller();
        withLanguageAccess(field, target, caller, () -> {
            field.setShort(target, value);
            return null;
        });
    }

    public static void reflectiveFieldSetInt(java.lang.reflect.Field field, Object target, int value)
            throws IllegalAccessException {
        guardSensitiveFieldMutation(field);
        Class<?> caller = originalReflectionCaller();
        withLanguageAccess(field, target, caller, () -> {
            field.setInt(target, value);
            return null;
        });
    }

    public static void reflectiveFieldSetLong(java.lang.reflect.Field field, Object target, long value)
            throws IllegalAccessException {
        guardSensitiveFieldMutation(field);
        Class<?> caller = originalReflectionCaller();
        withLanguageAccess(field, target, caller, () -> {
            field.setLong(target, value);
            return null;
        });
    }

    public static void reflectiveFieldSetFloat(java.lang.reflect.Field field, Object target, float value)
            throws IllegalAccessException {
        guardSensitiveFieldMutation(field);
        Class<?> caller = originalReflectionCaller();
        withLanguageAccess(field, target, caller, () -> {
            field.setFloat(target, value);
            return null;
        });
    }

    public static void reflectiveFieldSetDouble(java.lang.reflect.Field field, Object target, double value)
            throws IllegalAccessException {
        guardSensitiveFieldMutation(field);
        Class<?> caller = originalReflectionCaller();
        withLanguageAccess(field, target, caller, () -> {
            field.setDouble(target, value);
            return null;
        });
    }

    public static void reflectiveFieldSetAccessible(java.lang.reflect.Field field, boolean accessible) {
        if (accessible) guardAntiRatReflection(field.getDeclaringClass(), "private field accessibility change");
        field.setAccessible(accessible);
    }

    public static boolean reflectiveFieldTrySetAccessible(java.lang.reflect.Field field) {
        guardAntiRatReflection(field.getDeclaringClass(), "private field accessibility change");
        return field.trySetAccessible();
    }

    public static Object reflectiveMethodInvoke(Method method, Object target, Object[] arguments)
            throws IllegalAccessException, InvocationTargetException {
        if (method == null) throw new NullPointerException("method");
        Class<?> owner = method.getDeclaringClass();
        String name = method.getName();
        Object[] args = arguments == null ? new Object[0] : arguments;
        guardAntiRatReflection(owner, "reflective method invocation");

        if (owner == Method.class && name.equals("invoke") && target instanceof Method nested
                && args.length >= 2 && args[1] instanceof Object[] nestedArguments) {
            return reflectiveMethodInvoke(nested, args[0], nestedArguments);
        }
        if (owner == java.lang.reflect.Field.class && name.equals("get")
                && target instanceof java.lang.reflect.Field field) {
            return reflectiveFieldGet(field, args.length == 0 ? null : args[0]);
        }
        if (owner == java.lang.reflect.Field.class && target instanceof java.lang.reflect.Field field) {
            Object receiver = args.length == 0 ? null : args[0];
            switch (name) {
                case "getBoolean" -> { return reflectiveFieldGetBoolean(field, receiver); }
                case "getByte" -> { return reflectiveFieldGetByte(field, receiver); }
                case "getChar" -> { return reflectiveFieldGetChar(field, receiver); }
                case "getShort" -> { return reflectiveFieldGetShort(field, receiver); }
                case "getInt" -> { return reflectiveFieldGetInt(field, receiver); }
                case "getLong" -> { return reflectiveFieldGetLong(field, receiver); }
                case "getFloat" -> { return reflectiveFieldGetFloat(field, receiver); }
                case "getDouble" -> { return reflectiveFieldGetDouble(field, receiver); }
                case "set" -> { reflectiveFieldSet(field, receiver, args[1]); return null; }
                case "setBoolean" -> { reflectiveFieldSetBoolean(field, receiver, (Boolean) args[1]); return null; }
                case "setByte" -> { reflectiveFieldSetByte(field, receiver, (Byte) args[1]); return null; }
                case "setChar" -> { reflectiveFieldSetChar(field, receiver, (Character) args[1]); return null; }
                case "setShort" -> { reflectiveFieldSetShort(field, receiver, (Short) args[1]); return null; }
                case "setInt" -> { reflectiveFieldSetInt(field, receiver, (Integer) args[1]); return null; }
                case "setLong" -> { reflectiveFieldSetLong(field, receiver, (Long) args[1]); return null; }
                case "setFloat" -> { reflectiveFieldSetFloat(field, receiver, (Float) args[1]); return null; }
                case "setDouble" -> { reflectiveFieldSetDouble(field, receiver, (Double) args[1]); return null; }
                case "setAccessible" -> { reflectiveFieldSetAccessible(field, (Boolean) args[0]); return null; }
                case "trySetAccessible" -> { return reflectiveFieldTrySetAccessible(field); }
                default -> { }
            }
        }
        if (owner == Constructor.class && name.equals("newInstance") && target instanceof Constructor<?> nested) {
            Object[] nestedArguments = args.length > 0 && args[0] instanceof Object[] values
                    ? values : new Object[0];
            try {
                return reflectiveConstructorNewInstance(nested, nestedArguments);
            } catch (InstantiationException exception) {
                throw new InvocationTargetException(exception);
            }
        }
        if (isCredentialSecretMethod(owner.getName(), name)
                && TokenGuard.shouldDenySessionToken()) {
            return "";
        }
        if (owner.getName().equals("sun.misc.Unsafe") && target instanceof sun.misc.Unsafe unsafe) {
            Object dispatched = reflectivelyInvokeUnsafe(unsafe, method, args);
            if (dispatched != UNSAFE_NOT_DISPATCHED) return dispatched;
        }
        Object systemResult = reflectivelyReadSystemMetadata(owner, name, target, args);
        if (systemResult != REFLECTION_NOT_DISPATCHED) return systemResult;
        Object globalNetworkResult = reflectivelyManageGlobalNetworkState(owner, name, args);
        if (globalNetworkResult != REFLECTION_NOT_DISPATCHED) return globalNetworkResult;
        Object lookupResult = reflectivelyInvokeLookup(owner, name, target, args);
        if (lookupResult != REFLECTION_NOT_DISPATCHED) return lookupResult;
        guardReflectiveInvocation(owner, name, target, args);
        Class<?> caller = originalReflectionCaller();
        try {
            return method.invoke(target, args);
        } catch (IllegalAccessException denied) {
            if (!canUseLanguageAccess(caller, method, target)) throw denied;
            synchronized (method) {
                boolean restore = !method.isAccessible();
                try {
                    if (restore && !method.trySetAccessible()) throw denied;
                    return method.invoke(target, args);
                } catch (RuntimeException inaccessible) {
                    denied.addSuppressed(inaccessible);
                    throw denied;
                } finally {
                    if (restore) restoreAccessibility(method);
                }
            }
        }
    }

    public static Object reflectiveConstructorNewInstance(Constructor<?> constructor, Object[] arguments)
            throws InstantiationException, IllegalAccessException, InvocationTargetException {
        if (constructor == null) throw new NullPointerException("constructor");
        Object[] args = arguments == null ? new Object[0] : arguments;
        Class<?> owner = constructor.getDeclaringClass();
        guardAntiRatReflection(owner, "reflective construction");
        if ((owner == java.io.FileInputStream.class || owner == java.io.FileReader.class
                || owner == java.io.RandomAccessFile.class) && args.length > 0) {
            if (args[0] instanceof String path) guardFileRead(path);
            else if (args[0] instanceof File file) guardFileRead(file);
        } else if (owner == java.util.Scanner.class && args.length > 0) {
            if (args[0] instanceof File file) guardFileRead(file);
            else if (args[0] instanceof Path path) guardFileRead(path);
        } else if (Socket.class.isAssignableFrom(owner) && args.length >= 2 && args[1] instanceof Integer port) {
            if (args[0] instanceof String host) checkHostPort(host, port);
            else if (args[0] instanceof InetAddress host) checkHostPort(host, port);
        }
        Class<?> caller = originalReflectionCaller();
        try {
            return constructor.newInstance(args);
        } catch (IllegalAccessException denied) {
            if (!canUseLanguageAccess(caller, constructor, null)) throw denied;
            synchronized (constructor) {
                boolean restore = !constructor.isAccessible();
                try {
                    if (restore && !constructor.trySetAccessible()) throw denied;
                    return constructor.newInstance(args);
                } catch (RuntimeException inaccessible) {
                    denied.addSuppressed(inaccessible);
                    throw denied;
                } finally {
                    if (restore) restoreAccessibility(constructor);
                }
            }
        }
    }

    private static Class<?> originalReflectionCaller() {
        return REFLECTION_CALLER_WALKER.walk(frames -> frames
                .map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type != RuntimeHooks.class)
                .filter(type -> !type.getName().startsWith("java.lang.reflect."))
                .filter(type -> !type.getName().startsWith("jdk.internal.reflect."))
                .findFirst()
                .orElse(null));
    }

    private static boolean canUseLanguageAccess(Class<?> caller, java.lang.reflect.Member member, Object target) {
        if (caller == null || member == null) return false;
        Class<?> owner = member.getDeclaringClass();
        int modifiers = member.getModifiers();
        boolean sameRuntimePackage = caller.getModule() == owner.getModule()
                && caller.getPackageName().equals(owner.getPackageName());
        boolean nestmate = caller.getNestHost() == owner.getNestHost();

        if (Modifier.isPrivate(modifiers)) return nestmate;
        if (!Modifier.isPublic(modifiers) && !Modifier.isProtected(modifiers)) return sameRuntimePackage;
        if (Modifier.isProtected(modifiers)) {
            if (sameRuntimePackage) return true;
            if (member instanceof Constructor<?>) return false;
            if (!Modifier.isPublic(owner.getModifiers()) || !owner.isAssignableFrom(caller)) return false;
            return Modifier.isStatic(modifiers) || (target != null && caller.isInstance(target));
        }
        // A public member on a public class should already be accessible. Retrying only repairs the
        // package-private declaring-class case and never bypasses module export boundaries.
        return !Modifier.isPublic(owner.getModifiers()) && (sameRuntimePackage || nestmate);
    }

    private static <T> T withLanguageAccess(Field field, Object target, Class<?> caller,
                                             FieldAccess<T> operation) throws IllegalAccessException {
        try {
            return operation.run();
        } catch (IllegalAccessException denied) {
            if (!canUseLanguageAccess(caller, field, target)) throw denied;
            synchronized (field) {
                boolean restore = !field.isAccessible();
                try {
                    if (restore && !field.trySetAccessible()) throw denied;
                    return operation.run();
                } catch (RuntimeException inaccessible) {
                    denied.addSuppressed(inaccessible);
                    throw denied;
                } finally {
                    if (restore) restoreAccessibility(field);
                }
            }
        }
    }

    private static void restoreAccessibility(AccessibleObject object) {
        try {
            object.setAccessible(false);
        } catch (RuntimeException ignored) {
        }
    }

    @FunctionalInterface
    private interface FieldAccess<T> {
        T run() throws IllegalAccessException;
    }

    public static void guardDynamicCode() {
        ModIdentity source = ModIndex.findByCurrentStack();
        ScanResult scan = ScanRegistry.startupResult(source.id());
        boolean denied = !source.known() || AntiRatRuntime.runtimeLockedDown(source.id())
                || AntiRatRuntime.capabilityDenied(source.id(), Capability.DYNAMIC_CODE)
                || AntiRatRuntime.riskForMod(source.id()).atLeast(RiskLevel.HIGH)
                || (scan != null && (scan.quarantineRecommended()
                || scan.deniedCapabilities().contains(Capability.DYNAMIC_CODE)));
        if (!denied) return;
        reportOnce(ThreatType.DYNAMIC_CODE_EXECUTION, RiskLevel.CRITICAL,
                "Blocked dynamic code definition",
                "A risky or unattributed mod attempted to define executable bytecode at runtime.",
                source, "runtime-defined class", 94,
                "Remove the source mod; encrypted runtime class generation prevents complete static verification.",
                List.of("Bytecode content was not executed or persisted by AntiRat",
                        "Source failed dynamic-code capability policy"));
        throw new SecurityException("AntiRat blocked runtime code definition");
    }

    public static void guardUnsafeOperation() {
        if (!unsafeOperationDenied()) return;
        reportUnsafeDenied();
        throw new SecurityException("AntiRat blocked unrestricted Unsafe access");
    }

    private static boolean guardUnsafeOperationNonFatal() {
        if (!unsafeOperationDenied()) return false;
        reportUnsafeDenied();
        return true;
    }

    private static boolean unsafeOperationDenied() {
        ModIdentity source = ModIndex.findByCurrentStack();
        if (!source.known() || AntiRatRuntime.runtimeLockedDown(source.id())) return true;
        ScanResult scan = ScanRegistry.startupResult(source.id());
        return AntiRatRuntime.riskForMod(source.id()).atLeast(RiskLevel.HIGH)
                || AntiRatRuntime.capabilityDenied(source.id(), Capability.DYNAMIC_CODE)
                || scan == null
                || scan.quarantineRecommended()
                || scan.deniedCapabilities().contains(Capability.DYNAMIC_CODE)
                || (scan.highConfidence() && scan.riskLevel().atLeast(RiskLevel.HIGH));
    }

    private static void reportUnsafeDenied() {
        ModIdentity source = ModIndex.findByCurrentStack();
        reportOnce(ThreatType.DYNAMIC_CODE_EXECUTION, RiskLevel.CRITICAL,
                "Blocked unrestricted memory access",
                "A risky or unattributed mod attempted an Unsafe operation that can bypass Java access and instrumentation barriers.",
                source, "Unsafe memory API", 96,
                "Review the source mod; verified low-risk rendering and performance mods may use memory primitives without being quarantined.",
                List.of("No memory value or offset was captured", "The Unsafe operation did not execute"));
    }

    @SuppressWarnings("removal")
    public static void unsafeCopyMemory(sun.misc.Unsafe unsafe, long source, long destination, long bytes) {
        if (guardUnsafeOperationNonFatal()) return;
        unsafe.copyMemory(source, destination, bytes);
    }

    @SuppressWarnings("removal")
    public static void unsafeCopyMemory(
            sun.misc.Unsafe unsafe, Object source, long sourceOffset,
            Object destination, long destinationOffset, long bytes
    ) {
        if (guardUnsafeOperationNonFatal()) return;
        unsafe.copyMemory(source, sourceOffset, destination, destinationOffset, bytes);
    }

    @SuppressWarnings("removal")
    public static void unsafeSetMemory(sun.misc.Unsafe unsafe, long address, long bytes, byte value) {
        if (guardUnsafeOperationNonFatal()) return;
        unsafe.setMemory(address, bytes, value);
    }

    @SuppressWarnings("removal")
    public static void unsafeSetMemory(sun.misc.Unsafe unsafe, Object target, long offset, long bytes, byte value) {
        if (guardUnsafeOperationNonFatal()) return;
        unsafe.setMemory(target, offset, bytes, value);
    }

    @SuppressWarnings("removal")
    public static long unsafeAllocateMemory(sun.misc.Unsafe unsafe, long bytes) {
        if (guardUnsafeOperationNonFatal()) return 0L;
        return unsafe.allocateMemory(bytes);
    }

    @SuppressWarnings("removal")
    public static long unsafeReallocateMemory(sun.misc.Unsafe unsafe, long address, long bytes) {
        if (guardUnsafeOperationNonFatal()) return 0L;
        return unsafe.reallocateMemory(address, bytes);
    }

    @SuppressWarnings("removal")
    public static void unsafeFreeMemory(sun.misc.Unsafe unsafe, long address) {
        if (guardUnsafeOperationNonFatal()) return;
        unsafe.freeMemory(address);
    }

    @SuppressWarnings("removal")
    public static long unsafeGetAddress(sun.misc.Unsafe unsafe, long address) {
        if (guardUnsafeOperationNonFatal()) return 0L;
        return unsafe.getAddress(address);
    }

    @SuppressWarnings("removal")
    public static void unsafePutAddress(sun.misc.Unsafe unsafe, long address, long value) {
        if (guardUnsafeOperationNonFatal()) return;
        unsafe.putAddress(address, value);
    }

    public static void guardUnsafeField(java.lang.reflect.Field field) {
        if (field == null) return;
        guardAntiRatReflection(field.getDeclaringClass(), "Unsafe field-offset access");
        if (isSessionTokenField(field.getDeclaringClass().getName(), field.getName(), field.getType())
                || isCredentialObjectField(field.getDeclaringClass().getName(), field.getName(), field.getType())) {
            blockDirectSessionAccess("Unsafe field-offset access to a Minecraft credential carrier was denied");
            throw new SecurityException("AntiRat denied Unsafe credential field access");
        }
    }

    public static void guardUnsafeField(Class<?> owner, String fieldName) {
        guardAntiRatReflection(owner, "Unsafe named field-offset access");
        if (owner != null && isCredentialCarrierClass(owner.getName())
                && ("accessToken".equals(fieldName) || "field_1983".equals(fieldName))) {
            blockDirectSessionAccess("Unsafe named-field access to a Minecraft credential was denied");
            throw new SecurityException("AntiRat denied Unsafe credential field access");
        }
    }

    @SuppressWarnings("removal")
    public static long unsafeObjectFieldOffset(sun.misc.Unsafe unsafe, Field field) {
        guardUnsafeField(field);
        return unsafe.objectFieldOffset(field);
    }

    @SuppressWarnings("removal")
    public static long unsafeStaticFieldOffset(sun.misc.Unsafe unsafe, Field field) {
        guardUnsafeField(field);
        return unsafe.staticFieldOffset(field);
    }

    @SuppressWarnings("removal")
    public static Object unsafeStaticFieldBase(sun.misc.Unsafe unsafe, Field field) {
        guardUnsafeField(field);
        return unsafe.staticFieldBase(field);
    }

    @SuppressWarnings("removal")
    public static Object unsafeGetObject(sun.misc.Unsafe unsafe, Object target, long offset) {
        if (guardUnsafeReadTarget(target)) return "";
        return unsafe.getObject(target, offset);
    }

    @SuppressWarnings("removal")
    public static Object unsafeGetObjectVolatile(sun.misc.Unsafe unsafe, Object target, long offset) {
        if (guardUnsafeReadTarget(target)) return "";
        return unsafe.getObjectVolatile(target, offset);
    }

    @SuppressWarnings("removal")
    public static void unsafePutObject(sun.misc.Unsafe unsafe, Object target, long offset, Object value) {
        guardUnsafeWriteTarget(target);
        unsafe.putObject(target, offset, value);
    }

    @SuppressWarnings("removal")
    public static void unsafePutObjectVolatile(sun.misc.Unsafe unsafe, Object target, long offset, Object value) {
        guardUnsafeWriteTarget(target);
        unsafe.putObjectVolatile(target, offset, value);
    }

    @SuppressWarnings("removal")
    public static void unsafePutOrderedObject(sun.misc.Unsafe unsafe, Object target, long offset, Object value) {
        guardUnsafeWriteTarget(target);
        unsafe.putOrderedObject(target, offset, value);
    }

    @SuppressWarnings("removal")
    public static boolean unsafeCompareAndSwapObject(
            sun.misc.Unsafe unsafe, Object target, long offset, Object expected, Object value
    ) {
        if (guardUnsafeReadTarget(target)) return false;
        return unsafe.compareAndSwapObject(target, offset, expected, value);
    }

    @SuppressWarnings("removal")
    public static Object unsafeGetAndSetObject(
            sun.misc.Unsafe unsafe, Object target, long offset, Object value
    ) {
        if (guardUnsafeReadTarget(target)) return "";
        return unsafe.getAndSetObject(target, offset, value);
    }

    @SuppressWarnings("removal")
    public static Object unsafeAllocateInstance(sun.misc.Unsafe unsafe, Class<?> type)
            throws InstantiationException {
        if (type == null) throw new NullPointerException("type");
        guardAntiRatReflection(type, "Unsafe instance allocation");
        if (isSessionClass(type.getName())) {
            blockDirectSessionAccess("Unsafe allocation of Minecraft's Session class was denied");
            throw new SecurityException("AntiRat denied Unsafe Session allocation");
        }
        ModIdentity source = ModIndex.findByCurrentStack();
        ScanResult scan = ScanRegistry.startupResult(source.id());
        boolean denied = !source.known() || AntiRatRuntime.runtimeLockedDown(source.id())
                || AntiRatRuntime.riskForMod(source.id()).atLeast(RiskLevel.HIGH)
                || AntiRatRuntime.capabilityDenied(source.id(), Capability.DYNAMIC_CODE)
                || (scan != null && (scan.quarantineRecommended()
                || scan.deniedCapabilities().contains(Capability.DYNAMIC_CODE)));
        if (denied) guardUnsafeOperation();
        return unsafe.allocateInstance(type);
    }

    public static MethodHandles.Lookup privateLookupIn(
            Class<?> target, MethodHandles.Lookup caller
    ) throws IllegalAccessException {
        if (isCredentialCarrierClass(target == null ? "" : target.getName())) {
            blockDirectSessionAccess("Private MethodHandles access to a Minecraft credential carrier was denied");
            throw new IllegalAccessException("AntiRat denied private credential-carrier lookup");
        }
        guardAntiRatReflection(target, "private MethodHandles lookup");
        return MethodHandles.privateLookupIn(target, caller);
    }

    public static MethodHandle lookupFindStatic(
            MethodHandles.Lookup lookup, Class<?> owner, String name, MethodType type
    ) throws NoSuchMethodException, IllegalAccessException {
        guardLookupTarget(owner, name);
        String hook = staticMethodHandleHook(owner, name, type);
        if (hook != null) return MethodHandles.lookup().findStatic(RuntimeHooks.class, hook, type);
        return lookup.findStatic(owner, name, type);
    }

    public static MethodHandle lookupFindVirtual(
            MethodHandles.Lookup lookup, Class<?> owner, String name, MethodType type
    ) throws NoSuchMethodException, IllegalAccessException {
        if (isCredentialSecretMethod(owner == null ? "" : owner.getName(), name)) {
            return spoofedSessionGetter(owner, type);
        }
        guardLookupTarget(owner, name);
        VirtualHook hook = virtualMethodHandleHook(owner, name, type);
        if (hook != null) {
            MethodType hookType = type.insertParameterTypes(0, hook.receiver());
            MethodType requestedType = type.insertParameterTypes(0, owner);
            return MethodHandles.lookup().findStatic(RuntimeHooks.class, hook.name(), hookType).asType(requestedType);
        }
        return lookup.findVirtual(owner, name, type);
    }

    public static MethodHandle lookupFindSpecial(
            MethodHandles.Lookup lookup, Class<?> owner, String name, MethodType type, Class<?> specialCaller
    ) throws NoSuchMethodException, IllegalAccessException {
        if (isCredentialSecretMethod(owner == null ? "" : owner.getName(), name)) {
            return spoofedSessionGetter(specialCaller == null ? owner : specialCaller, type);
        }
        guardLookupTarget(owner, name);
        guardLookupTarget(specialCaller, "special caller");
        return lookup.findSpecial(owner, name, type, specialCaller);
    }

    public static MethodHandle lookupFindConstructor(
            MethodHandles.Lookup lookup, Class<?> owner, MethodType type
    ) throws NoSuchMethodException, IllegalAccessException {
        guardLookupTarget(owner, "constructor");
        String hook = constructorMethodHandleHook(owner, type);
        if (hook != null) {
            return MethodHandles.lookup().findStatic(RuntimeHooks.class, hook, type.changeReturnType(owner));
        }
        return lookup.findConstructor(owner, type);
    }

    public static MethodHandle lookupUnreflect(
            MethodHandles.Lookup lookup, Method method
    ) throws IllegalAccessException {
        if (method == null) throw new NullPointerException("method");
        Class<?> owner = method.getDeclaringClass();
        MethodType type = MethodType.methodType(method.getReturnType(), method.getParameterTypes());
        if (isCredentialSecretMethod(owner.getName(), method.getName())) {
            return spoofedSessionGetter(owner, type);
        }
        guardLookupTarget(owner, method.getName());
        try {
            if (Modifier.isStatic(method.getModifiers())) {
                String hook = staticMethodHandleHook(owner, method.getName(), type);
                if (hook != null) return MethodHandles.lookup().findStatic(RuntimeHooks.class, hook, type);
            } else {
                VirtualHook hook = virtualMethodHandleHook(owner, method.getName(), type);
                if (hook != null) {
                    MethodType hookType = type.insertParameterTypes(0, hook.receiver());
                    MethodType requestedType = type.insertParameterTypes(0, owner);
                    return MethodHandles.lookup().findStatic(RuntimeHooks.class, hook.name(), hookType)
                            .asType(requestedType);
                }
            }
        } catch (NoSuchMethodException impossible) {
            throw new IllegalAccessException("AntiRat runtime hook is unavailable: " + impossible.getMessage());
        }
        return lookup.unreflect(method);
    }

    public static MethodHandle lookupUnreflectSpecial(
            MethodHandles.Lookup lookup, Method method, Class<?> specialCaller
    ) throws IllegalAccessException {
        if (method == null) throw new NullPointerException("method");
        if (isCredentialSecretMethod(method.getDeclaringClass().getName(), method.getName())) {
            MethodType type = MethodType.methodType(method.getReturnType(), method.getParameterTypes());
            return spoofedSessionGetter(specialCaller == null ? method.getDeclaringClass() : specialCaller, type);
        }
        guardLookupTarget(method.getDeclaringClass(), method.getName());
        guardLookupTarget(specialCaller, "special caller");
        return lookup.unreflectSpecial(method, specialCaller);
    }

    public static MethodHandle lookupUnreflectConstructor(
            MethodHandles.Lookup lookup, Constructor<?> constructor
    ) throws IllegalAccessException {
        if (constructor == null) throw new NullPointerException("constructor");
        Class<?> owner = constructor.getDeclaringClass();
        guardLookupTarget(owner, "constructor");
        MethodType type = MethodType.methodType(void.class, constructor.getParameterTypes());
        String hook = constructorMethodHandleHook(owner, type);
        if (hook != null) {
            try {
                return MethodHandles.lookup().findStatic(RuntimeHooks.class, hook, type.changeReturnType(owner));
            } catch (NoSuchMethodException impossible) {
                throw new IllegalAccessException("AntiRat constructor hook is unavailable: " + impossible.getMessage());
            }
        }
        return lookup.unreflectConstructor(constructor);
    }

    public static MethodHandle lookupFindGetter(
            MethodHandles.Lookup lookup, Class<?> owner, String name, Class<?> type
    ) throws NoSuchFieldException, IllegalAccessException {
        guardLookupField(owner, name);
        return lookup.findGetter(owner, name, type);
    }

    public static MethodHandle lookupFindSetter(
            MethodHandles.Lookup lookup, Class<?> owner, String name, Class<?> type
    ) throws NoSuchFieldException, IllegalAccessException {
        guardLookupField(owner, name);
        return lookup.findSetter(owner, name, type);
    }

    public static MethodHandle lookupFindStaticGetter(
            MethodHandles.Lookup lookup, Class<?> owner, String name, Class<?> type
    ) throws NoSuchFieldException, IllegalAccessException {
        guardLookupField(owner, name);
        return lookup.findStaticGetter(owner, name, type);
    }

    public static MethodHandle lookupFindStaticSetter(
            MethodHandles.Lookup lookup, Class<?> owner, String name, Class<?> type
    ) throws NoSuchFieldException, IllegalAccessException {
        guardLookupField(owner, name);
        return lookup.findStaticSetter(owner, name, type);
    }

    public static MethodHandle lookupUnreflectGetter(
            MethodHandles.Lookup lookup, java.lang.reflect.Field field
    ) throws IllegalAccessException {
        guardUnsafeField(field);
        return lookup.unreflectGetter(field);
    }

    public static MethodHandle lookupUnreflectSetter(
            MethodHandles.Lookup lookup, java.lang.reflect.Field field
    ) throws IllegalAccessException {
        guardUnsafeField(field);
        return lookup.unreflectSetter(field);
    }

    public static VarHandle lookupFindVarHandle(
            MethodHandles.Lookup lookup, Class<?> owner, String name, Class<?> type
    ) throws NoSuchFieldException, IllegalAccessException {
        guardLookupField(owner, name);
        return lookup.findVarHandle(owner, name, type);
    }

    public static VarHandle lookupFindStaticVarHandle(
            MethodHandles.Lookup lookup, Class<?> owner, String name, Class<?> type
    ) throws NoSuchFieldException, IllegalAccessException {
        guardLookupField(owner, name);
        return lookup.findStaticVarHandle(owner, name, type);
    }

    public static VarHandle lookupUnreflectVarHandle(
            MethodHandles.Lookup lookup, java.lang.reflect.Field field
    ) throws IllegalAccessException {
        guardUnsafeField(field);
        return lookup.unreflectVarHandle(field);
    }

    public static String directSessionTokenMethod(Object session) {
        blockDirectSessionAccess("MethodHandle access to Minecraft's session token was denied");
        return "";
    }

    public static String directSessionTokenField(Object session, String fieldName) {
        blockDirectSessionAccess("Direct bytecode access to Minecraft's session-token field was denied");
        return "";
    }

    private static MethodHandle spoofedSessionGetter(Class<?> owner, MethodType type) throws IllegalAccessException {
        blockDirectSessionAccess("MethodHandle access to Minecraft's session token was denied");
        try {
            MethodHandle hook = MethodHandles.lookup().findStatic(RuntimeHooks.class, "directSessionTokenMethod",
                    MethodType.methodType(String.class, Object.class));
            return hook.asType(type.insertParameterTypes(0, owner));
        } catch (NoSuchMethodException impossible) {
            throw new IllegalAccessException("AntiRat session hook is unavailable");
        }
    }

    private static void guardLookupField(Class<?> owner, String name) throws NoSuchFieldException {
        if (owner == null) throw new NullPointerException("owner");
        java.lang.reflect.Field field = owner.getDeclaredField(name);
        guardUnsafeField(field);
    }

    private static void guardLookupTarget(Class<?> owner, String name) {
        if (owner == null) throw new NullPointerException("owner");
        guardAntiRatReflection(owner, "MethodHandle lookup for " + name);
    }

    private static String staticMethodHandleHook(Class<?> owner, String name, MethodType type) {
        if (owner == Files.class) {
            return switch (name + type.toMethodDescriptorString()) {
                case "newInputStream(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/io/InputStream;" -> "filesNewInputStream";
                case "readAllBytes(Ljava/nio/file/Path;)[B" -> "filesReadAllBytes";
                case "readString(Ljava/nio/file/Path;)Ljava/lang/String;",
                        "readString(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)Ljava/lang/String;" -> "filesReadString";
                case "newBufferedReader(Ljava/nio/file/Path;)Ljava/io/BufferedReader;",
                        "newBufferedReader(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)Ljava/io/BufferedReader;" -> "filesNewBufferedReader";
                case "readAllLines(Ljava/nio/file/Path;)Ljava/util/List;",
                        "readAllLines(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)Ljava/util/List;" -> "filesReadAllLines";
                case "lines(Ljava/nio/file/Path;)Ljava/util/stream/Stream;",
                        "lines(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)Ljava/util/stream/Stream;" -> "filesLines";
                case "copy(Ljava/nio/file/Path;Ljava/io/OutputStream;)J",
                        "copy(Ljava/nio/file/Path;Ljava/nio/file/Path;[Ljava/nio/file/CopyOption;)Ljava/nio/file/Path;" -> "filesCopy";
                case "mismatch(Ljava/nio/file/Path;Ljava/nio/file/Path;)J" -> "filesMismatch";
                case "createLink(Ljava/nio/file/Path;Ljava/nio/file/Path;)Ljava/nio/file/Path;" -> "filesCreateLink";
                case "createSymbolicLink(Ljava/nio/file/Path;Ljava/nio/file/Path;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/file/Path;" -> "filesCreateSymbolicLink";
                case "move(Ljava/nio/file/Path;Ljava/nio/file/Path;[Ljava/nio/file/CopyOption;)Ljava/nio/file/Path;" -> "filesMove";
                case "newByteChannel(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/nio/channels/SeekableByteChannel;",
                        "newByteChannel(Ljava/nio/file/Path;Ljava/util/Set;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/SeekableByteChannel;" -> "filesNewByteChannel";
                default -> null;
            };
        }
        if (owner == FileChannel.class) {
            String signature = name + type.toMethodDescriptorString();
            if (signature.equals("open(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/nio/channels/FileChannel;")
                    || signature.equals("open(Ljava/nio/file/Path;Ljava/util/Set;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/FileChannel;")) {
                return "fileChannelOpen";
            }
        }
        if (owner == AsynchronousFileChannel.class) {
            String signature = name + type.toMethodDescriptorString();
            if (signature.equals("open(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/nio/channels/AsynchronousFileChannel;")
                    || signature.equals("open(Ljava/nio/file/Path;Ljava/util/Set;Ljava/util/concurrent/ExecutorService;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/AsynchronousFileChannel;")) {
                return "asynchronousFileChannelOpen";
            }
        }
        if (owner == SocketChannel.class && name.equals("open") && type.parameterCount() == 1) {
            return "socketChannelOpen";
        }
        if (owner == InetAddress.class) {
            if (name.equals("getByName")) return "inetAddressGetByName";
            if (name.equals("getAllByName")) return "inetAddressGetAllByName";
        }
        if (owner == System.class) {
            return switch (name + type.toMethodDescriptorString()) {
                case "getenv(Ljava/lang/String;)Ljava/lang/String;", "getenv()Ljava/util/Map;" -> "systemGetenv";
                case "getProperty(Ljava/lang/String;)Ljava/lang/String;",
                        "getProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" -> "systemGetProperty";
                case "getProperties()Ljava/util/Properties;" -> "systemGetProperties";
                case "load(Ljava/lang/String;)V" -> "systemLoad";
                case "loadLibrary(Ljava/lang/String;)V" -> "systemLoadLibrary";
                default -> null;
            };
        }
        if (owner == DriverManager.class) {
            return switch (name + type.toMethodDescriptorString()) {
                case "getConnection(Ljava/lang/String;)Ljava/sql/Connection;",
                        "getConnection(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;",
                        "getConnection(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/sql/Connection;" ->
                        "driverManagerGetConnection";
                default -> null;
            };
        }
        if (owner == ProcessBuilder.class && name.equals("startPipeline")
                && type.toMethodDescriptorString().equals("(Ljava/util/List;)Ljava/util/List;")) {
            return "processStartPipeline";
        }
        if (owner == ProxySelector.class && name.equals("setDefault")
                && type.toMethodDescriptorString().equals("(Ljava/net/ProxySelector;)V")) {
            return "proxySelectorSetDefault";
        }
        if (owner == CookieHandler.class && name.equals("setDefault")
                && type.toMethodDescriptorString().equals("(Ljava/net/CookieHandler;)V")) {
            return "cookieHandlerSetDefault";
        }
        return null;
    }

    private static String constructorMethodHandleHook(Class<?> owner, MethodType type) {
        String descriptor = type.toMethodDescriptorString();
        if (owner == java.io.FileInputStream.class) {
            return switch (descriptor) {
                case "(Ljava/lang/String;)V", "(Ljava/io/File;)V" -> "fileInputStreamCreate";
                default -> null;
            };
        }
        if (owner == java.io.FileReader.class) {
            return switch (descriptor) {
                case "(Ljava/lang/String;)V", "(Ljava/io/File;)V",
                        "(Ljava/lang/String;Ljava/nio/charset/Charset;)V",
                        "(Ljava/io/File;Ljava/nio/charset/Charset;)V" -> "fileReaderCreate";
                default -> null;
            };
        }
        if (owner == java.io.RandomAccessFile.class) {
            return switch (descriptor) {
                case "(Ljava/lang/String;Ljava/lang/String;)V",
                        "(Ljava/io/File;Ljava/lang/String;)V" -> "randomAccessFileCreate";
                default -> null;
            };
        }
        if (owner == java.util.Scanner.class) {
            return switch (descriptor) {
                case "(Ljava/io/File;)V", "(Ljava/io/File;Ljava/lang/String;)V",
                        "(Ljava/io/File;Ljava/nio/charset/Charset;)V",
                        "(Ljava/nio/file/Path;)V", "(Ljava/nio/file/Path;Ljava/lang/String;)V",
                        "(Ljava/nio/file/Path;Ljava/nio/charset/Charset;)V" -> "scannerCreate";
                default -> null;
            };
        }
        if (owner == Socket.class) {
            return switch (descriptor) {
                case "(Ljava/lang/String;I)V", "(Ljava/net/InetAddress;I)V",
                        "(Ljava/lang/String;ILjava/net/InetAddress;I)V",
                        "(Ljava/net/InetAddress;ILjava/net/InetAddress;I)V" -> "socketCreate";
                default -> null;
            };
        }
        return null;
    }

    private static VirtualHook virtualMethodHandleHook(Class<?> owner, String name, MethodType type) {
        String signature = name + type.toMethodDescriptorString();
        if (owner.getName().equals("sun.misc.Unsafe")) {
            VirtualHook hook = switch (signature) {
                case "objectFieldOffset(Ljava/lang/reflect/Field;)J" -> new VirtualHook("unsafeObjectFieldOffset", sun.misc.Unsafe.class);
                case "staticFieldOffset(Ljava/lang/reflect/Field;)J" -> new VirtualHook("unsafeStaticFieldOffset", sun.misc.Unsafe.class);
                case "staticFieldBase(Ljava/lang/reflect/Field;)Ljava/lang/Object;" -> new VirtualHook("unsafeStaticFieldBase", sun.misc.Unsafe.class);
                case "getObject(Ljava/lang/Object;J)Ljava/lang/Object;" -> new VirtualHook("unsafeGetObject", sun.misc.Unsafe.class);
                case "getObjectVolatile(Ljava/lang/Object;J)Ljava/lang/Object;" -> new VirtualHook("unsafeGetObjectVolatile", sun.misc.Unsafe.class);
                case "putObject(Ljava/lang/Object;JLjava/lang/Object;)V" -> new VirtualHook("unsafePutObject", sun.misc.Unsafe.class);
                case "putObjectVolatile(Ljava/lang/Object;JLjava/lang/Object;)V" -> new VirtualHook("unsafePutObjectVolatile", sun.misc.Unsafe.class);
                case "putOrderedObject(Ljava/lang/Object;JLjava/lang/Object;)V" -> new VirtualHook("unsafePutOrderedObject", sun.misc.Unsafe.class);
                case "compareAndSwapObject(Ljava/lang/Object;JLjava/lang/Object;Ljava/lang/Object;)Z" -> new VirtualHook("unsafeCompareAndSwapObject", sun.misc.Unsafe.class);
                case "getAndSetObject(Ljava/lang/Object;JLjava/lang/Object;)Ljava/lang/Object;" -> new VirtualHook("unsafeGetAndSetObject", sun.misc.Unsafe.class);
                case "allocateInstance(Ljava/lang/Class;)Ljava/lang/Object;" -> new VirtualHook("unsafeAllocateInstance", sun.misc.Unsafe.class);
                default -> null;
            };
            if (hook != null) return hook;
            if (isDangerousUnsafeOperation(name, type.toMethodDescriptorString())) guardUnsafeOperation();
            return null;
        }
        if (owner == URL.class) {
            return switch (signature) {
                case "openConnection()Ljava/net/URLConnection;",
                        "openConnection(Ljava/net/Proxy;)Ljava/net/URLConnection;" -> new VirtualHook("urlOpenConnection", URL.class);
                case "openStream()Ljava/io/InputStream;" -> new VirtualHook("urlOpenStream", URL.class);
                case "getContent()Ljava/lang/Object;", "getContent([Ljava/lang/Class;)Ljava/lang/Object;" -> new VirtualHook("urlGetContent", URL.class);
                default -> null;
            };
        }
        if (owner == HttpClient.class) {
            if (signature.equals("send(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)Ljava/net/http/HttpResponse;")) {
                return new VirtualHook("httpSend", HttpClient.class);
            }
            if (signature.equals("sendAsync(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;)Ljava/util/concurrent/CompletableFuture;")
                    || signature.equals("sendAsync(Ljava/net/http/HttpRequest;Ljava/net/http/HttpResponse$BodyHandler;Ljava/net/http/HttpResponse$PushPromiseHandler;)Ljava/util/concurrent/CompletableFuture;")) {
                return new VirtualHook("httpSendAsync", HttpClient.class);
            }
        }
        if (owner == WebSocket.Builder.class && signature.equals(
                "buildAsync(Ljava/net/URI;Ljava/net/http/WebSocket$Listener;)Ljava/util/concurrent/CompletableFuture;")) {
            return new VirtualHook("webSocketBuildAsync", WebSocket.Builder.class);
        }
        if (owner == Socket.class && (signature.equals("connect(Ljava/net/SocketAddress;)V")
                || signature.equals("connect(Ljava/net/SocketAddress;I)V"))) {
            return new VirtualHook("socketConnect", Socket.class);
        }
        if (owner == SocketChannel.class && signature.equals("connect(Ljava/net/SocketAddress;)Z")) {
            return new VirtualHook("socketChannelConnect", SocketChannel.class);
        }
        if (owner == AsynchronousSocketChannel.class && (signature.equals(
                "connect(Ljava/net/SocketAddress;)Ljava/util/concurrent/Future;")
                || signature.equals("connect(Ljava/net/SocketAddress;Ljava/lang/Object;Ljava/nio/channels/CompletionHandler;)V"))) {
            return new VirtualHook("asynchronousSocketConnect", AsynchronousSocketChannel.class);
        }
        if (owner == DatagramSocket.class) {
            if (signature.equals("connect(Ljava/net/SocketAddress;)V")
                    || signature.equals("connect(Ljava/net/InetAddress;I)V")) {
                return new VirtualHook("datagramConnect", DatagramSocket.class);
            }
            if (signature.equals("send(Ljava/net/DatagramPacket;)V")) {
                return new VirtualHook("datagramSend", DatagramSocket.class);
            }
        }
        if (owner == DatagramChannel.class) {
            if (signature.equals("connect(Ljava/net/SocketAddress;)Ljava/nio/channels/DatagramChannel;")) {
                return new VirtualHook("datagramChannelConnect", DatagramChannel.class);
            }
            if (signature.equals("send(Ljava/nio/ByteBuffer;Ljava/net/SocketAddress;)I")) {
                return new VirtualHook("datagramChannelSend", DatagramChannel.class);
            }
        }
        if (SocketFactory.class.isAssignableFrom(owner) && Set.of(
                "createSocket(Ljava/lang/String;I)Ljava/net/Socket;",
                "createSocket(Ljava/net/InetAddress;I)Ljava/net/Socket;",
                "createSocket(Ljava/lang/String;ILjava/net/InetAddress;I)Ljava/net/Socket;",
                "createSocket(Ljava/net/InetAddress;ILjava/net/InetAddress;I)Ljava/net/Socket;"
        ).contains(signature)) {
            return new VirtualHook("socketFactoryCreateSocket", SocketFactory.class);
        }
        if (owner == Desktop.class && signature.equals("browse(Ljava/net/URI;)V")) {
            return new VirtualHook("desktopBrowse", Desktop.class);
        }
        if (owner == ProcessBuilder.class && signature.equals("start()Ljava/lang/Process;")) {
            return new VirtualHook("processStart", ProcessBuilder.class);
        }
        if (owner == ProcessBuilder.class && signature.equals("environment()Ljava/util/Map;")) {
            return new VirtualHook("processBuilderEnvironment", ProcessBuilder.class);
        }
        if (owner == RuntimeMXBean.class) {
            if (signature.equals("getInputArguments()Ljava/util/List;")) {
                return new VirtualHook("runtimeMxBeanGetInputArguments", RuntimeMXBean.class);
            }
            if (signature.equals("getSystemProperties()Ljava/util/Map;")) {
                return new VirtualHook("runtimeMxBeanGetSystemProperties", RuntimeMXBean.class);
            }
        }
        if (owner == Runtime.class && name.equals("exec") && Set.of(
                "exec(Ljava/lang/String;)Ljava/lang/Process;",
                "exec([Ljava/lang/String;)Ljava/lang/Process;",
                "exec(Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/Process;",
                "exec([Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/Process;",
                "exec(Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;)Ljava/lang/Process;",
                "exec([Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;)Ljava/lang/Process;"
        ).contains(signature)) return new VirtualHook("runtimeExec", Runtime.class);
        if (owner == Runtime.class && signature.equals("load(Ljava/lang/String;)V")) {
            return new VirtualHook("runtimeLoad", Runtime.class);
        }
        if (owner == Runtime.class && signature.equals("loadLibrary(Ljava/lang/String;)V")) {
            return new VirtualHook("runtimeLoadLibrary", Runtime.class);
        }
        if (owner == FileSystemProvider.class) {
            return switch (signature) {
                case "newInputStream(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/io/InputStream;" -> new VirtualHook("providerNewInputStream", FileSystemProvider.class);
                case "newByteChannel(Ljava/nio/file/Path;Ljava/util/Set;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/SeekableByteChannel;" -> new VirtualHook("providerNewByteChannel", FileSystemProvider.class);
                case "newFileChannel(Ljava/nio/file/Path;Ljava/util/Set;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/FileChannel;" -> new VirtualHook("providerNewFileChannel", FileSystemProvider.class);
                case "newAsynchronousFileChannel(Ljava/nio/file/Path;Ljava/util/Set;Ljava/util/concurrent/ExecutorService;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/channels/AsynchronousFileChannel;" -> new VirtualHook("providerNewAsynchronousFileChannel", FileSystemProvider.class);
                default -> null;
            };
        }
        if (owner == java.lang.reflect.Field.class) {
            return switch (signature) {
                case "get(Ljava/lang/Object;)Ljava/lang/Object;" -> new VirtualHook("reflectiveFieldGet", java.lang.reflect.Field.class);
                case "getBoolean(Ljava/lang/Object;)Z" -> new VirtualHook("reflectiveFieldGetBoolean", java.lang.reflect.Field.class);
                case "getByte(Ljava/lang/Object;)B" -> new VirtualHook("reflectiveFieldGetByte", java.lang.reflect.Field.class);
                case "getChar(Ljava/lang/Object;)C" -> new VirtualHook("reflectiveFieldGetChar", java.lang.reflect.Field.class);
                case "getShort(Ljava/lang/Object;)S" -> new VirtualHook("reflectiveFieldGetShort", java.lang.reflect.Field.class);
                case "getInt(Ljava/lang/Object;)I" -> new VirtualHook("reflectiveFieldGetInt", java.lang.reflect.Field.class);
                case "getLong(Ljava/lang/Object;)J" -> new VirtualHook("reflectiveFieldGetLong", java.lang.reflect.Field.class);
                case "getFloat(Ljava/lang/Object;)F" -> new VirtualHook("reflectiveFieldGetFloat", java.lang.reflect.Field.class);
                case "getDouble(Ljava/lang/Object;)D" -> new VirtualHook("reflectiveFieldGetDouble", java.lang.reflect.Field.class);
                case "set(Ljava/lang/Object;Ljava/lang/Object;)V" -> new VirtualHook("reflectiveFieldSet", java.lang.reflect.Field.class);
                case "setBoolean(Ljava/lang/Object;Z)V" -> new VirtualHook("reflectiveFieldSetBoolean", java.lang.reflect.Field.class);
                case "setByte(Ljava/lang/Object;B)V" -> new VirtualHook("reflectiveFieldSetByte", java.lang.reflect.Field.class);
                case "setChar(Ljava/lang/Object;C)V" -> new VirtualHook("reflectiveFieldSetChar", java.lang.reflect.Field.class);
                case "setShort(Ljava/lang/Object;S)V" -> new VirtualHook("reflectiveFieldSetShort", java.lang.reflect.Field.class);
                case "setInt(Ljava/lang/Object;I)V" -> new VirtualHook("reflectiveFieldSetInt", java.lang.reflect.Field.class);
                case "setLong(Ljava/lang/Object;J)V" -> new VirtualHook("reflectiveFieldSetLong", java.lang.reflect.Field.class);
                case "setFloat(Ljava/lang/Object;F)V" -> new VirtualHook("reflectiveFieldSetFloat", java.lang.reflect.Field.class);
                case "setDouble(Ljava/lang/Object;D)V" -> new VirtualHook("reflectiveFieldSetDouble", java.lang.reflect.Field.class);
                case "setAccessible(Z)V" -> new VirtualHook("reflectiveFieldSetAccessible", java.lang.reflect.Field.class);
                case "trySetAccessible()Z" -> new VirtualHook("reflectiveFieldTrySetAccessible", java.lang.reflect.Field.class);
                default -> null;
            };
        }
        if (owner == Method.class && signature.equals(
                "invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;")) {
            return new VirtualHook("reflectiveMethodInvoke", Method.class);
        }
        if (owner == Constructor.class && signature.equals("newInstance([Ljava/lang/Object;)Ljava/lang/Object;")) {
            return new VirtualHook("reflectiveConstructorNewInstance", Constructor.class);
        }
        if (owner.getName().equals("java.lang.ProcessHandle$Info")) {
            if (signature.equals("arguments()Ljava/util/Optional;")) {
                return new VirtualHook("processInfoArguments", ProcessHandle.Info.class);
            }
            if (signature.equals("commandLine()Ljava/util/Optional;")) {
                return new VirtualHook("processInfoCommandLine", ProcessHandle.Info.class);
            }
        }
        return null;
    }

    private record VirtualHook(String name, Class<?> receiver) {
    }

    private static void checkSensitiveRead(Path path) {
        SensitivePathPolicy.Decision decision = SensitivePathPolicy.classify(path);
        if (!decision.block()) return;
        ModIdentity source = ModIndex.findByCurrentStack();
        reportOnce(ThreatType.SENSITIVE_FILE_ACCESS, RiskLevel.CRITICAL,
                "Blocked credential-store read", "A mod attempted to read a protected credential-bearing file.",
                source, decision.category(), 97,
                "Minecraft mods should use documented game APIs rather than reading account, browser, or chat-client stores.",
                decision.evidence());
        throw new SecurityException("AntiRat blocked read access to a protected " + decision.category());
    }

    private static void checkUri(URI uri) {
        if (uri == null) return;
        if ("file".equalsIgnoreCase(uri.getScheme())) {
            try {
                checkSensitiveRead(Path.of(uri));
            } catch (IllegalArgumentException invalid) {
                throw new SecurityException("AntiRat could not validate file URL access", invalid);
            }
            return;
        }
        ModIdentity source = ModIndex.findByCurrentStack();
        NetworkDecision decision = SensitiveNetworkPolicy.classify(uri, source);
        if (decision.report()) {
            reportOnce(ThreatType.NETWORK_REQUEST, decision.riskLevel(), decision.title(), decision.summary(), source,
                    GuardedProxySelector.sanitizeTarget(uri), decision.accuracy(), decision.tip(), decision.evidence());
        }
        if (decision.block()) {
            throw new SecurityException("AntiRat blocked outbound request to " + GuardedProxySelector.sanitizeTarget(uri));
        }
    }

    private static void checkProcess(String executable) {
        ModIdentity source = ModIndex.findByCurrentStack();
        String leaf = executableLeaf(executable);
        boolean interpreter = Set.of("powershell", "powershell.exe", "pwsh", "cmd", "cmd.exe", "sh", "bash",
                "zsh", "fish", "dash", "csh", "ksh", "busybox", "wscript", "wscript.exe", "cscript",
                "cscript.exe", "osascript", "python", "python3", "python.exe", "python3.exe", "perl", "ruby",
                "node", "node.exe", "php", "lua", "java", "java.exe", "jshell", "jshell.exe", "curl", "wget",
                "certutil", "certutil.exe", "bitsadmin", "bitsadmin.exe", "mshta", "mshta.exe", "rundll32",
                "rundll32.exe", "reg", "reg.exe", "sqlite3")
                .contains(leaf);
        ScanResult scan = ScanRegistry.startupResult(source.id());
        // A child process escapes every in-JVM barrier. Calls reaching this hook originate in transformed
        // third-party code, so fail closed even when its static scan was otherwise clean.
        reportOnce(ThreatType.PROCESS_EXECUTION, RiskLevel.CRITICAL,
                "Blocked process escape", "A mod attempted to launch code outside AntiRat's JVM enforcement boundary.",
                source, leaf.isBlank() ? "child process" : leaf, 94,
                "Remove the source mod unless its external-process behavior is independently verified.",
                List.of("Command arguments were not captured", interpreter
                        ? "Shell, script interpreter, downloader, or secondary runtime invocation"
                        : scan != null && scan.deniedCapabilities().contains(Capability.PROCESS_EXECUTION)
                        ? "Startup scan also denied process capability"
                        : "External processes cannot be safely contained by a client-only JAR"));
        throw new SecurityException("AntiRat blocked mod-initiated process execution");
    }

    private static void checkNativeLoad(String name) {
        ModIdentity source = ModIndex.findByCurrentStack();
        ScanResult scan = ScanRegistry.startupResult(source.id());
        boolean denied = !source.known() || AntiRatRuntime.runtimeLockedDown(source.id())
                || AntiRatRuntime.riskForMod(source.id()).atLeast(RiskLevel.HIGH)
                || (scan != null && (scan.quarantineRecommended()
                || scan.deniedCapabilities().contains(Capability.DYNAMIC_CODE)));
        if (!denied) return;
        reportOnce(ThreatType.PROCESS_EXECUTION, RiskLevel.CRITICAL,
                "Blocked native-code escape", "A mod attempted to load code outside JVM instrumentation coverage.",
                source, "native library", 93,
                "Native code can read memory and files without Java hooks; remove the source mod.",
                List.of("Library path/name was not recorded",
                        scan != null && scan.deniedCapabilities().contains(Capability.DYNAMIC_CODE)
                                ? "Startup scan also restricted native/dynamic execution"
                                : "The source was already high-risk or unattributed"));
        throw new SecurityException("AntiRat blocked mod-initiated native-code loading");
    }

    private static void guardReflectiveInvocation(Class<?> owner, String name, Object target, Object[] args) {
        if (owner == Files.class) {
            guardReflectedFilesCall(name, args);
        } else if ((owner == FileChannel.class || owner == AsynchronousFileChannel.class)
                && name.equals("open") && args.length > 0 && args[0] instanceof Path path) {
            checkSensitiveRead(path);
        } else if (target instanceof FileSystemProvider && args.length > 0 && args[0] instanceof Path path
                && Set.of("newInputStream", "newByteChannel", "newFileChannel",
                "newAsynchronousFileChannel").contains(name)) {
            checkSensitiveRead(path);
        } else if (target instanceof URL url && Set.of("openConnection", "openStream", "getContent").contains(name)) {
            checkReflectedUrl(url);
        } else if (target instanceof URLConnection connection
                && Set.of("connect", "getInputStream", "getOutputStream", "getContent").contains(name)) {
            checkReflectedUrl(connection.getURL());
        } else if (target instanceof HttpClient && (name.equals("send") || name.equals("sendAsync"))
                && args.length > 0 && args[0] instanceof HttpRequest request) {
            checkUri(request.uri());
        } else if (target instanceof WebSocket.Builder && name.equals("buildAsync")
                && args.length > 0 && args[0] instanceof URI uri) {
            checkUri(uri);
        } else if (owner == InetAddress.class && (name.equals("getByName") || name.equals("getAllByName"))
                && args.length > 0 && args[0] instanceof String host) {
            checkHostPort(host, 53);
        } else if (owner == SocketChannel.class && name.equals("open") && args.length > 0
                && args[0] instanceof SocketAddress address) {
            checkSocketAddress(address);
        } else if ((target instanceof Socket || target instanceof SocketChannel
                || target instanceof AsynchronousSocketChannel) && name.equals("connect")
                && args.length > 0 && args[0] instanceof SocketAddress address) {
            checkSocketAddress(address);
        } else if (target instanceof SocketFactory && name.equals("createSocket") && args.length >= 2
                && args[1] instanceof Integer port) {
            if (args[0] instanceof String host) checkHostPort(host, port);
            else if (args[0] instanceof InetAddress host) checkHostPort(host, port);
        } else if (target instanceof DatagramSocket && name.equals("send") && args.length > 0
                && args[0] instanceof DatagramPacket packet) {
            checkHostPort(packet.getAddress(), packet.getPort());
        } else if (target instanceof DatagramSocket && name.equals("connect") && args.length > 0) {
            if (args[0] instanceof SocketAddress address) checkSocketAddress(address);
            else if (args.length > 1 && args[0] instanceof InetAddress host && args[1] instanceof Integer port) {
                checkHostPort(host, port);
            }
        } else if (target instanceof DatagramChannel && name.equals("connect") && args.length > 0
                && args[0] instanceof SocketAddress address) {
            checkSocketAddress(address);
        } else if (target instanceof DatagramChannel && name.equals("send") && args.length > 1
                && args[1] instanceof SocketAddress address) {
            checkSocketAddress(address);
        } else if (target instanceof ProcessBuilder builder && name.equals("start")) {
            checkProcess(builder.command().isEmpty() ? "" : builder.command().getFirst());
        } else if (owner == ProcessBuilder.class && name.equals("startPipeline")
                && args.length > 0 && args[0] instanceof List<?> builders) {
            for (Object value : builders) {
                if (value instanceof ProcessBuilder builder) {
                    checkProcess(builder.command().isEmpty() ? "" : builder.command().getFirst());
                }
            }
        } else if (target instanceof Runtime && name.equals("exec") && args.length > 0) {
            checkProcess(args[0] instanceof String[] command ? first(command) : String.valueOf(args[0]));
        } else if (target instanceof Runtime && name.startsWith("load")) {
            checkNativeLoad(args.length == 0 ? "" : String.valueOf(args[0]));
        } else if (owner == System.class && (name.equals("load") || name.equals("loadLibrary"))) {
            checkNativeLoad(args.length == 0 ? "" : String.valueOf(args[0]));
        } else if (owner == DriverManager.class && name.equals("getConnection")
                && args.length > 0 && args[0] instanceof String url) {
            checkJdbcUrl(url);
        } else if (target instanceof Desktop && name.equals("browse") && args.length > 0
                && args[0] instanceof URI uri) {
            checkUri(uri);
        } else if (ClassLoader.class.isAssignableFrom(owner) && name.startsWith("defineClass")) {
            guardDynamicCode();
        } else if (owner.getName().equals("java.lang.invoke.MethodHandles$Lookup")
                && (name.startsWith("defineClass") || name.startsWith("defineHiddenClass"))) {
            guardDynamicCode();
        }
    }

    private static void guardReflectedFilesCall(String name, Object[] args) {
        if (args.length == 0) return;
        if (name.equals("createLink") && args.length > 1 && args[1] instanceof Path existing) {
            checkSensitiveRead(existing);
            return;
        }
        if (name.equals("createSymbolicLink") && args[0] instanceof Path link
                && args.length > 1 && args[1] instanceof Path target) {
            Path parent = link.toAbsolutePath().getParent();
            Path resolved = target.isAbsolute() || parent == null ? target : parent.resolve(target);
            checkSensitiveRead(resolved.normalize());
            return;
        }
        if (!(args[0] instanceof Path first)) return;
        if (name.startsWith("read") || name.startsWith("newInput") || name.equals("lines")
                || name.equals("newBufferedReader") || name.equals("newByteChannel")
                || name.equals("copy") || name.equals("move") || name.equals("mismatch")) {
            checkSensitiveRead(first);
        }
        if (name.equals("mismatch") && args.length > 1 && args[1] instanceof Path second) {
            checkSensitiveRead(second);
        }
    }

    private static void checkReflectedUrl(URL url) {
        try {
            checkUri(toUri(url));
        } catch (IOException exception) {
            throw new SecurityException("AntiRat could not validate reflected URL access", exception);
        }
    }

    private static void guardSensitiveFieldMutation(java.lang.reflect.Field field) {
        guardAntiRatReflection(field.getDeclaringClass(), "private field mutation");
        if (isSessionTokenField(field.getDeclaringClass().getName(), field.getName(), field.getType())) {
            blockDirectSessionAccess("Reflective mutation of Minecraft's session-token field was denied");
            throw new SecurityException("AntiRat denied Session credential mutation");
        }
        if (isCredentialObjectField(field.getDeclaringClass().getName(), field.getName(), field.getType())) {
            blockDirectSessionAccess("Reflective mutation of an authenticated Minecraft service was denied");
            throw new SecurityException("AntiRat denied credential-service mutation");
        }
    }

    private static void checkJdbcUrl(String url) {
        if (url == null) return;
        String lower = url.toLowerCase(java.util.Locale.ROOT);
        String target;
        if (lower.startsWith("jdbc:sqlite:")) target = url.substring("jdbc:sqlite:".length());
        else if (lower.startsWith("jdbc:h2:file:")) target = url.substring("jdbc:h2:file:".length());
        else if (lower.startsWith("jdbc:hsqldb:file:")) target = url.substring("jdbc:hsqldb:file:".length());
        else if (lower.startsWith("jdbc:derby:")) target = url.substring("jdbc:derby:".length());
        else return;
        int options = target.indexOf('?');
        if (options >= 0) target = target.substring(0, options);
        if (target.isBlank() || target.equalsIgnoreCase(":memory:") || target.startsWith("mem:")) return;
        try {
            Path path = target.startsWith("file:") ? Path.of(URI.create(target)) : Path.of(target);
            checkSensitiveRead(path);
        } catch (IllegalArgumentException invalid) {
            if (lower.contains("login data") || lower.contains("cookies.sqlite")
                    || lower.contains("launcher_accounts") || lower.contains("local storage")) {
                throw new SecurityException("AntiRat blocked an ambiguous credential-database URL", invalid);
            }
        }
    }

    private static boolean guardUnsafeReadTarget(Object target) {
        if (target == null) return false;
        guardAntiRatReflection(target.getClass(), "Unsafe memory read");
        if (isCredentialCarrierClass(target.getClass().getName())) {
            blockDirectSessionAccess("Unsafe memory access to a Minecraft credential carrier was denied");
            return true;
        }
        return false;
    }

    private static final Object REFLECTION_NOT_DISPATCHED = new Object();
    private static final Object UNSAFE_NOT_DISPATCHED = new Object();

    private static Object reflectivelyReadSystemMetadata(
            Class<?> owner, String name, Object target, Object[] args
    ) {
        if (owner == System.class) {
            return switch (name) {
                case "getenv" -> args.length == 0 ? systemGetenv() : systemGetenv((String) args[0]);
                case "getProperty" -> args.length == 1
                        ? systemGetProperty((String) args[0])
                        : systemGetProperty((String) args[0], (String) args[1]);
                case "getProperties" -> systemGetProperties();
                default -> REFLECTION_NOT_DISPATCHED;
            };
        }
        if (owner.getName().equals("java.lang.ProcessHandle$Info") && target instanceof ProcessHandle.Info info) {
            if (name.equals("arguments")) return processInfoArguments(info);
            if (name.equals("commandLine")) return processInfoCommandLine(info);
        }
        if (target instanceof ProcessBuilder builder && name.equals("environment")) {
            return processBuilderEnvironment(builder);
        }
        if (target instanceof RuntimeMXBean bean) {
            if (name.equals("getInputArguments")) return runtimeMxBeanGetInputArguments(bean);
            if (name.equals("getSystemProperties")) return runtimeMxBeanGetSystemProperties(bean);
        }
        return REFLECTION_NOT_DISPATCHED;
    }

    private static Object reflectivelyManageGlobalNetworkState(
            Class<?> owner, String name, Object[] args
    ) {
        if (!name.equals("setDefault") || args.length != 1) return REFLECTION_NOT_DISPATCHED;
        if (owner == ProxySelector.class) {
            proxySelectorSetDefault((ProxySelector) args[0]);
            return null;
        }
        if (owner == CookieHandler.class) {
            cookieHandlerSetDefault((CookieHandler) args[0]);
            return null;
        }
        return REFLECTION_NOT_DISPATCHED;
    }

    private static Object reflectivelyInvokeLookup(
            Class<?> owner, String name, Object target, Object[] args
    ) throws InvocationTargetException {
        try {
            if (owner == MethodHandles.class && name.equals("privateLookupIn") && args.length == 2) {
                return privateLookupIn((Class<?>) args[0], (MethodHandles.Lookup) args[1]);
            }
            if (owner != MethodHandles.Lookup.class || !(target instanceof MethodHandles.Lookup lookup)) {
                return REFLECTION_NOT_DISPATCHED;
            }
            return switch (name) {
                case "findStatic" -> lookupFindStatic(lookup, (Class<?>) args[0], (String) args[1],
                        (MethodType) args[2]);
                case "findVirtual" -> lookupFindVirtual(lookup, (Class<?>) args[0], (String) args[1],
                        (MethodType) args[2]);
                case "findSpecial" -> lookupFindSpecial(lookup, (Class<?>) args[0], (String) args[1],
                        (MethodType) args[2], (Class<?>) args[3]);
                case "findConstructor" -> lookupFindConstructor(lookup, (Class<?>) args[0],
                        (MethodType) args[1]);
                case "unreflect" -> lookupUnreflect(lookup, (Method) args[0]);
                case "unreflectSpecial" -> lookupUnreflectSpecial(lookup, (Method) args[0], (Class<?>) args[1]);
                case "unreflectConstructor" -> lookupUnreflectConstructor(lookup, (Constructor<?>) args[0]);
                case "findGetter" -> lookupFindGetter(lookup, (Class<?>) args[0], (String) args[1],
                        (Class<?>) args[2]);
                case "findSetter" -> lookupFindSetter(lookup, (Class<?>) args[0], (String) args[1],
                        (Class<?>) args[2]);
                case "findStaticGetter" -> lookupFindStaticGetter(lookup, (Class<?>) args[0], (String) args[1],
                        (Class<?>) args[2]);
                case "findStaticSetter" -> lookupFindStaticSetter(lookup, (Class<?>) args[0], (String) args[1],
                        (Class<?>) args[2]);
                case "unreflectGetter" -> lookupUnreflectGetter(lookup, (Field) args[0]);
                case "unreflectSetter" -> lookupUnreflectSetter(lookup, (Field) args[0]);
                case "findVarHandle" -> lookupFindVarHandle(lookup, (Class<?>) args[0], (String) args[1],
                        (Class<?>) args[2]);
                case "findStaticVarHandle" -> lookupFindStaticVarHandle(lookup, (Class<?>) args[0],
                        (String) args[1], (Class<?>) args[2]);
                case "unreflectVarHandle" -> lookupUnreflectVarHandle(lookup, (Field) args[0]);
                default -> REFLECTION_NOT_DISPATCHED;
            };
        } catch (SecurityException blocked) {
            throw blocked;
        } catch (ReflectiveOperationException failure) {
            throw new InvocationTargetException(failure);
        }
    }

    @SuppressWarnings("removal")
    private static Object reflectivelyInvokeUnsafe(sun.misc.Unsafe unsafe, Method method, Object[] args) {
        String signature = method.getName() + MethodType.methodType(method.getReturnType(), method.getParameterTypes())
                .toMethodDescriptorString();
        return switch (signature) {
            case "objectFieldOffset(Ljava/lang/reflect/Field;)J" -> unsafeObjectFieldOffset(unsafe, (Field) args[0]);
            case "staticFieldOffset(Ljava/lang/reflect/Field;)J" -> unsafeStaticFieldOffset(unsafe, (Field) args[0]);
            case "staticFieldBase(Ljava/lang/reflect/Field;)Ljava/lang/Object;" -> unsafeStaticFieldBase(unsafe, (Field) args[0]);
            case "getObject(Ljava/lang/Object;J)Ljava/lang/Object;" ->
                    unsafeGetObject(unsafe, args[0], ((Number) args[1]).longValue());
            case "getObjectVolatile(Ljava/lang/Object;J)Ljava/lang/Object;" ->
                    unsafeGetObjectVolatile(unsafe, args[0], ((Number) args[1]).longValue());
            case "putObject(Ljava/lang/Object;JLjava/lang/Object;)V" -> {
                unsafePutObject(unsafe, args[0], ((Number) args[1]).longValue(), args[2]);
                yield null;
            }
            case "putObjectVolatile(Ljava/lang/Object;JLjava/lang/Object;)V" -> {
                unsafePutObjectVolatile(unsafe, args[0], ((Number) args[1]).longValue(), args[2]);
                yield null;
            }
            case "putOrderedObject(Ljava/lang/Object;JLjava/lang/Object;)V" -> {
                unsafePutOrderedObject(unsafe, args[0], ((Number) args[1]).longValue(), args[2]);
                yield null;
            }
            case "compareAndSwapObject(Ljava/lang/Object;JLjava/lang/Object;Ljava/lang/Object;)Z" ->
                    unsafeCompareAndSwapObject(unsafe, args[0], ((Number) args[1]).longValue(), args[2], args[3]);
            case "getAndSetObject(Ljava/lang/Object;JLjava/lang/Object;)Ljava/lang/Object;" ->
                    unsafeGetAndSetObject(unsafe, args[0], ((Number) args[1]).longValue(), args[2]);
            case "allocateInstance(Ljava/lang/Class;)Ljava/lang/Object;" -> {
                try {
                    yield unsafeAllocateInstance(unsafe, (Class<?>) args[0]);
                } catch (InstantiationException failure) {
                    throw new IllegalStateException("Unsafe allocation failed", failure);
                }
            }
            case "copyMemory(JJJ)V" -> {
                unsafeCopyMemory(unsafe, ((Number) args[0]).longValue(),
                        ((Number) args[1]).longValue(), ((Number) args[2]).longValue());
                yield null;
            }
            case "copyMemory(Ljava/lang/Object;JLjava/lang/Object;JJ)V" -> {
                unsafeCopyMemory(unsafe, args[0], ((Number) args[1]).longValue(), args[2],
                        ((Number) args[3]).longValue(), ((Number) args[4]).longValue());
                yield null;
            }
            case "setMemory(JJB)V" -> {
                unsafeSetMemory(unsafe, ((Number) args[0]).longValue(),
                        ((Number) args[1]).longValue(), ((Number) args[2]).byteValue());
                yield null;
            }
            case "setMemory(Ljava/lang/Object;JJB)V" -> {
                unsafeSetMemory(unsafe, args[0], ((Number) args[1]).longValue(),
                        ((Number) args[2]).longValue(), ((Number) args[3]).byteValue());
                yield null;
            }
            case "allocateMemory(J)J" -> unsafeAllocateMemory(unsafe, ((Number) args[0]).longValue());
            case "reallocateMemory(JJ)J" -> unsafeReallocateMemory(unsafe,
                    ((Number) args[0]).longValue(), ((Number) args[1]).longValue());
            case "freeMemory(J)V" -> {
                unsafeFreeMemory(unsafe, ((Number) args[0]).longValue());
                yield null;
            }
            case "getAddress(J)J" -> unsafeGetAddress(unsafe, ((Number) args[0]).longValue());
            case "putAddress(JJ)V" -> {
                unsafePutAddress(unsafe, ((Number) args[0]).longValue(), ((Number) args[1]).longValue());
                yield null;
            }
            default -> {
                if (isDangerousUnsafeOperation(method.getName(),
                        MethodType.methodType(method.getReturnType(), method.getParameterTypes())
                                .toMethodDescriptorString())) {
                    guardUnsafeOperation();
                }
                if (args.length >= 2 && args[0] != null && args[1] instanceof Number
                        && (method.getName().startsWith("get") || method.getName().startsWith("put")
                        || method.getName().startsWith("compareAnd") || method.getName().startsWith("getAnd"))) {
                    if (method.getName().startsWith("get") && guardUnsafeReadTarget(args[0])) {
                        throw new SecurityException("AntiRat denied reflective Unsafe access to Session memory");
                    }
                    if (!method.getName().startsWith("get")) guardUnsafeWriteTarget(args[0]);
                }
                yield UNSAFE_NOT_DISPATCHED;
            }
        };
    }

    private static boolean isDangerousUnsafeOperation(String name, String descriptor) {
        if (name.startsWith("define") || name.equals("allocateMemory") || name.equals("reallocateMemory")
                || name.equals("freeMemory") || name.equals("setMemory") || name.equals("copyMemory")
                || name.equals("getAddress") || name.equals("putAddress")) return true;
        return descriptor.startsWith("(J") && (name.startsWith("get") || name.startsWith("put"));
    }

    private static void guardUnsafeWriteTarget(Object target) {
        if (target == null) return;
        guardAntiRatReflection(target.getClass(), "Unsafe memory mutation");
        if (isCredentialCarrierClass(target.getClass().getName())) {
            blockDirectSessionAccess("Unsafe mutation of a Minecraft credential carrier was denied");
            throw new SecurityException("AntiRat denied Unsafe credential-carrier mutation");
        }
    }

    private static void guardAntiRatReflection(Class<?> owner, String operation) {
        if (owner == null || !owner.getName().startsWith("com.antirat.")) return;
        ModIdentity source = ModIndex.findByCurrentStack();
        reportOnce(ThreatType.DYNAMIC_CODE_EXECUTION, RiskLevel.CRITICAL,
                "Blocked AntiRat tampering",
                "A mod attempted reflective access to AntiRat's private enforcement state.",
                source, "AntiRat internals", 98,
                "Remove the source mod; security tools should not be modified by ordinary client mods.",
                List.of("Blocked operation: " + operation, "No private field value was read or recorded"));
        throw new SecurityException("AntiRat blocked reflective access to its enforcement state");
    }

    private static boolean isSensitiveSecretName(String name) {
        if (name == null) return false;
        String normalized = name.toLowerCase(java.util.Locale.ROOT).replace('-', '_').replace('.', '_');
        return normalized.contains("access_token") || normalized.contains("accesstoken")
                || normalized.contains("client_token") || normalized.contains("clienttoken")
                || normalized.contains("refresh_token") || normalized.contains("refreshtoken")
                || normalized.contains("session_token") || normalized.contains("sessiontoken")
                || normalized.contains("discord_token") || normalized.contains("auth_token")
                || normalized.endsWith("_password") || normalized.endsWith("_passwd")
                || normalized.endsWith("_secret") || normalized.endsWith("_credential");
    }

    private static boolean isCommandProperty(String name) {
        return name != null && (name.equalsIgnoreCase("sun.java.command")
                || name.equalsIgnoreCase("jdk.module.main.class"));
    }

    static String[] redactArguments(String[] arguments) {
        String[] redacted = arguments.clone();
        boolean redactNext = false;
        for (int index = 0; index < redacted.length; index++) {
            String argument = redacted[index];
            if (redactNext) {
                redacted[index] = "<redacted>";
                redactNext = false;
                continue;
            }
            if (argument == null) continue;
            int equals = argument.indexOf('=');
            String key = equals >= 0 ? argument.substring(0, equals) : argument;
            String normalized = key.replaceFirst("^(?:-[dD]|--?)", "");
            if (isSensitiveSecretName(normalized) || normalized.equalsIgnoreCase("accessToken")
                    || normalized.equalsIgnoreCase("clientToken")) {
                if (equals >= 0) redacted[index] = argument.substring(0, equals + 1) + "<redacted>";
                else redactNext = true;
            }
        }
        return redacted;
    }

    static String redactCommandLine(String commandLine) {
        if (commandLine == null || commandLine.isBlank()) return commandLine;
        String redacted = commandLine;
        String[] names = {"accessToken", "access_token", "clientToken", "client_token", "refreshToken",
                "refresh_token", "sessionToken", "session_token", "discord_token", "auth_token"};
        for (String name : names) {
            redacted = redacted.replaceAll("(?i)(--?" + java.util.regex.Pattern.quote(name)
                    + "(?:=|\\s+))([^\\s]+)", "$1<redacted>");
        }
        return redacted;
    }

    private static void reportMetadataProtection(String title, String target, boolean highConfidence) {
        ModIdentity source = ModIndex.findByCurrentStack();
        reportOnce(ThreatType.SESSION_TOKEN_ACCESS, highConfidence ? RiskLevel.HIGH : RiskLevel.MEDIUM,
                title,
                "AntiRat withheld credential-bearing process metadata from mod code.",
                source, target, highConfidence ? 92 : 80,
                "Mods should use documented game APIs instead of reading launcher or host-process secrets.",
                List.of("Secret values were neither returned nor recorded"));
    }

    private static void blockDirectSessionAccess(String summary) {
        ModIdentity source = ModIndex.findByCurrentStack();
        reportOnce(ThreatType.SESSION_TOKEN_ACCESS, RiskLevel.CRITICAL,
                "Direct session-token access prevented", summary, source, "Minecraft session field", 98,
                "Use Minecraft's normal session API; direct field access is always denied to mods.",
                List.of("The credential value was not read, logged, or stored"));
    }

    private static void reportOnce(
            ThreatType type, RiskLevel risk, String title, String summary, ModIdentity source,
            String target, int accuracy, String tip, List<String> evidence
    ) {
        long now = System.currentTimeMillis();
        String key = type.name() + '|' + source.id() + '|' + title + '|' + target;
        Long previous = LAST_REPORT.put(key, now);
        if (previous != null && now - previous <= REPORT_SUPPRESS_MS) return;
        AntiRatRuntime.report(ThreatEvent.create(type, risk, title, summary, source.id(), source.name(), "", target,
                true, accuracy, tip, evidence));
    }

    private static URI toUri(URL url) throws IOException {
        try {
            return url.toURI();
        } catch (java.net.URISyntaxException exception) {
            throw new IOException("Invalid URL", exception);
        }
    }

    public static void checkSocketAddress(SocketAddress address) {
        if (address instanceof java.net.InetSocketAddress inet) {
            String host = inet.getHostString();
            checkHostPort(host, inet.getPort());
        }
    }

    private static URI socketUri(String host, int port) {
        if (host == null || host.isBlank()) return URI.create("http://invalid.invalid/");
        String bracketed = host.indexOf(':') >= 0 && !host.startsWith("[") ? '[' + host + ']' : host;
        try {
            return URI.create("http://" + bracketed + ':' + Math.max(0, port) + '/');
        } catch (IllegalArgumentException ignored) {
            return URI.create("http://invalid.invalid/");
        }
    }

    private static boolean isSessionTokenField(String owner, String field, Class<?> type) {
        if (type != String.class) return false;
        if (isSessionClass(owner)) return field.equals("accessToken") || field.equals("field_1983");
        return (owner.equals("com.mojang.authlib.minecraft.client.MinecraftClient")
                || owner.equals("com.mojang.authlib.yggdrasil.request.JoinMinecraftServerRequest"))
                && field.equals("accessToken");
    }

    private static boolean isSessionClass(String name) {
        return name.equals("net.minecraft.client.session.Session")
                || name.equals("net.minecraft.class_320")
                || name.equals("net.minecraft.client.User");
    }

    private static boolean isCredentialCarrierClass(String name) {
        return isSessionClass(name)
                || name.equals("net.minecraft.client.MinecraftClient")
                || name.equals("net.minecraft.class_310")
                || name.equals("net.minecraft.client.Minecraft")
                || name.equals("com.mojang.authlib.minecraft.client.MinecraftClient")
                || name.equals("com.mojang.authlib.yggdrasil.YggdrasilUserApiService")
                || name.equals("com.mojang.authlib.yggdrasil.request.JoinMinecraftServerRequest");
    }

    private static boolean isCredentialObjectField(String owner, String field, Class<?> type) {
        String typeName = type == null ? "" : type.getName();
        if ((owner.equals("net.minecraft.client.MinecraftClient") || owner.equals("net.minecraft.class_310"))
                && (field.equals("userApiService") || field.equals("field_26902"))) {
            return typeName.equals("com.mojang.authlib.minecraft.UserApiService");
        }
        return owner.equals("com.mojang.authlib.yggdrasil.YggdrasilUserApiService")
                && field.equals("minecraftClient")
                && typeName.equals("com.mojang.authlib.minecraft.client.MinecraftClient");
    }

    private static boolean isCredentialSecretMethod(String owner, String name) {
        if (isSessionClass(owner)) {
            return name.equals("getAccessToken") || name.equals("method_1674")
                    || name.equals("getSessionId") || name.equals("method_1675");
        }
        return owner.equals("com.mojang.authlib.yggdrasil.request.JoinMinecraftServerRequest")
                && (name.equals("accessToken") || name.equals("toString"));
    }

    private static String first(String[] command) {
        return command == null || command.length == 0 ? "" : command[0];
    }

    private static String executableLeaf(String command) {
        if (command == null || command.isBlank()) return "";
        String first = command.strip().split("\\s+", 2)[0].replace('\\', '/');
        int slash = first.lastIndexOf('/');
        return (slash >= 0 ? first.substring(slash + 1) : first).toLowerCase(java.util.Locale.ROOT);
    }
}
