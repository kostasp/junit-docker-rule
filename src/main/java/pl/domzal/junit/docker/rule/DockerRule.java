package pl.domzal.junit.docker.rule;

import java.io.IOException;
import java.net.Socket;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import com.spotify.docker.client.messages.*;
import org.apache.commons.lang.StringUtils;
import org.junit.Rule;
import org.junit.rules.ExternalResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.spotify.docker.client.DefaultDockerClient;
import com.spotify.docker.client.DockerCertificateException;
import com.spotify.docker.client.DockerClient;
import com.spotify.docker.client.DockerClient.ListImagesParam;
import com.spotify.docker.client.DockerClient.LogsParam;
import com.spotify.docker.client.DockerException;
import com.spotify.docker.client.DockerRequestException;
import com.spotify.docker.client.ImageNotFoundException;
import com.spotify.docker.client.LogStream;

import pl.domzal.junit.docker.rule.WaitForUnit.WaitForCondition;

/**
 * In order to be able to use this DockerRule the docker service should be installed to
 * the underlying running host and it should be available to the running host's user
 * Simple docker container junit {@link Rule}.<br/>
 * Instances should be created via builder:
 * <pre>
 *  &#064;Rule
 *  DockerRule container = DockerRule.builder()
 *      . //configuration directives
 *      .build();
 * </pre>
 * <br/>
 * Inspired by and loosely based on <a href="https://gist.github.com/mosheeshel/c427b43c36b256731a0b">osheeshel/Docker
 * ContainerRule</a>.
 */
public class DockerRule extends ExternalResource {

    public static final String DEFAULT_DOCKER_NET_PROTOCOL_TCP = "/tcp";
    private static final int STOP_TIMEOUT = 5;
    private static final int SHORT_ID_LEN = 12;
    private static Logger log = LoggerFactory.getLogger(DockerRule.class);
    private final DockerRuleBuilder builder;
    private final String imageNameWithTag;
    private final DockerClient dockerClient;

    private ContainerCreation container;
    private String containerShortId;
    private String containerIp;
    private String containerGateway;
    private Map<String, List<PortBinding>> containerPorts;

    private DockerLogs dockerLogs;
    //this flag will be used to safeguard that no containers build outside the DockerRule context will be shutdown
    private AtomicBoolean containerStartedOutsideDockerRuleContext = new AtomicBoolean(false);

    DockerRule(DockerRuleBuilder builder) {
        this.builder = builder;
        this.imageNameWithTag = imageNameWithTag(builder.imageName());
        try {
            dockerClient = DefaultDockerClient.fromEnv().build();
            log.debug("server.info: {}", dockerClient.info());
            log.debug("server.version: {}", dockerClient.version());
            if (builder.imageAlwaysPull() || !imageAvailable(dockerClient, imageNameWithTag)) {
                dockerClient.pull(imageNameWithTag);
                log.debug("Pulling Image : {}", imageNameWithTag);
            }
        } catch (ImageNotFoundException e) {
            throw new ImagePullException(String.format("Image '%s' not found", imageNameWithTag), e);
        } catch (DockerCertificateException | DockerException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }


    /**
     * Builder to specify parameters and produce {@link DockerRule} instance.
     */
    public static DockerRuleBuilder builder() {
        return new DockerRuleBuilder();
    }

    private static boolean isPortAvailable(int port, String host) {
        Socket s = null;
        try {
            s = new Socket(host, port);

            // If the code makes it this far without an exception it means
            // something is using the port and has responded.
            log.warn("--------------Port " + port + " is not available");
            return false;
        } catch (IOException e) {
            return true;
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (IOException e) {
                    throw new RuntimeException("You should handle this error.", e);
                }
            }
        }
    }

    /**
     * Create and start container.<br/>
     * This is {@link ExternalResource#before()} made available as public - it may be helpful in scenarios
     * when you want to use {@link DockerRule} and operate it manually.
     */
    @Override
    public final void before() throws Throwable {
        boolean skipImagePull = isDockerImageWithSameNameRunning(dockerClient, builder);
        if (skipImagePull) {
            log.warn("An container with the same image name {} is already up and running. SKIPPING The creation part",
                    builder.imageName());
            containerStartedOutsideDockerRuleContext.set(true);
            return;
        }
        boolean portConflictWithExistingContainers = portConflictExists(dockerClient, builder);
        if (portConflictWithExistingContainers) {
            log.warn("A conflict on ports has been found skipping the creation of container for image {}",
                    builder.imageName());
            containerStartedOutsideDockerRuleContext.set(true);
            return;
        }

        HostConfig hostConfig = HostConfig.builder()//
                .publishAllPorts(builder.publishAllPorts())//
                .portBindings(builder.hostPortBindings())//
                .binds(builder.binds())
                .links(builder.links())
                .extraHosts(builder.extraHosts())
                .build();
        ContainerConfig containerConfig = ContainerConfig.builder()
                .hostConfig(hostConfig)//
                .image(imageNameWithTag)//
                .env(builder.env())//
                .networkDisabled(false)//
                .exposedPorts(builder.containerExposedPorts())
                .entrypoint(builder.entrypoint())
                .cmd(builder.cmd()).build();
        try {
            this.container = dockerClient.createContainer(containerConfig);
            this.containerShortId = StringUtils.left(container.id(), SHORT_ID_LEN);
            log.info("container {} created, id {}, short id {}", imageNameWithTag, container.id(), containerShortId);
            log.debug("rule before {}", containerShortId);

            dockerClient.startContainer(container.id());
            log.debug("{} started", containerShortId);

            attachLogs(dockerClient, container.id());

            ContainerInfo containerInfo = dockerClient.inspectContainer(container.id());
            containerIp = containerInfo.networkSettings().ipAddress();
            containerPorts = containerInfo.networkSettings().ports();
            containerGateway = containerInfo.networkSettings().gateway();
            if (builder.waitForMessage() != null) {
                waitForMessage();
            }
            logNetworkSettings();
            //sleep for 4 seconds in order to wait the docker resources to be available. E.g when registering
            // an elasticsearch or rabbit or redis and it takes long to be available
            Thread.sleep(7000l);
        } catch (DockerRequestException e) {
            throw new IllegalStateException(e.message(), e);
        } catch (DockerException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Will check docker images with the same names to be running on this host
     *
     * @param dockerClient
     * @param dockerRuleBuilder
     * @return true in case a docker image with the same name already running
     */
    private boolean isDockerImageWithSameNameRunning(DockerClient dockerClient, DockerRuleBuilder dockerRuleBuilder) {
        try {
            List<Container> dockerAliveContainers = dockerClient.listContainers();
            for (Container container : dockerAliveContainers) {
                if (container.image().equalsIgnoreCase(dockerRuleBuilder.imageName())) {
                    return true;
                }
            }
            return false;
        } catch (DockerException | InterruptedException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * Will check for port conflicts both on the existing docker containers that might already run
     * an on this host
     *
     * @param dockerClient
     * @param dockerRuleBuilder
     * @return true in case a port of the container conflicts with another service (container or native host's service)
     */
    private boolean portConflictExists(DockerClient dockerClient, DockerRuleBuilder dockerRuleBuilder) {
        try {
            List<Container> dockerAliveContainers = dockerClient.listContainers();
            for (Container container : dockerAliveContainers) {
                Set<String> exposedPorts = dockerRuleBuilder.containerExposedPorts();
                List<Container.PortMapping> portMappings = container.ports();
                for (Container.PortMapping portMapping : portMappings) {
                    if (exposedPorts.contains(ExposePortBindingBuilder.containerBindWithProtocol(
                            portMapping.getPublicPort()))) {
                        log.warn("Discovered port {} conflict for image {} from the containerId {}",
                                portMapping.getPublicPort(), dockerRuleBuilder.imageName(), container.imageId());
                        return true;
                    }

                }
            }
            Set<String> exposedPorts = dockerRuleBuilder.containerExposedPorts();
            for (String portWithProtocol : exposedPorts) {
                if (!isPortAvailable(ExposePortBindingBuilder.containerBindWithOutProtocol(portWithProtocol),
                        "localhost")) {
                    log.warn("Discovered port {} conflict for image {}", portWithProtocol,
                            dockerRuleBuilder.imageName());
                    return true;
                }
            }


            return false;
        } catch (DockerException | InterruptedException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private void attachLogs(DockerClient dockerClient, String containerId) throws IOException, InterruptedException {
        dockerLogs = new DockerLogs(dockerClient, containerId);
        if (builder.stdoutWriter() != null) {
            dockerLogs.setStdoutWriter(builder.stdoutWriter());
        }
        if (builder.stderrWriter() != null) {
            dockerLogs.setStderrWriter(builder.stderrWriter());
        }
        dockerLogs.start();
    }

    private boolean imageAvailable(DockerClient dockerClient, String imageName) throws DockerException,
            InterruptedException {
        String imageNameWithTag = imageNameWithTag(imageName);
        List<Image> listImages = dockerClient.listImages(ListImagesParam.danglingImages(false));
        for (Image image : listImages) {
            if (image.repoTags().contains(imageNameWithTag)) {
                log.debug("image '{}' found", imageNameWithTag);
                return true;
            }
        }
        log.debug("image '{}' not found", imageNameWithTag);
        return false;
    }

    private String imageNameWithTag(String imageName) {
        if (!StringUtils.contains(imageName, ':')) {
            return imageName + ":latest";
        } else {
            return imageName;
        }
    }

    private void waitForMessage() throws TimeoutException, InterruptedException {
        final String waitForMessage = builder.waitForMessage();
        log.info("{} waiting for log message '{}'", containerShortId, waitForMessage);
        new WaitForUnit(TimeUnit.SECONDS, builder.waitForMessageSeconds(), new WaitForUnit.WaitForCondition() {
            @Override
            public boolean isConditionMet() {
                return getLog().contains(waitForMessage);
            }

            @Override
            public String timeoutMessage() {
                return String.format("Timeout waiting for '%s'", waitForMessage);
            }
        }).startWaiting();
        log.debug("{} message '{}' found", containerShortId, waitForMessage);
    }

    /**
     * Stop and remove container.<br/>
     * This is {@link ExternalResource#before()} made available as public - it may be helpful in scenarios
     * when you want to use {@link DockerRule} and operate it manually.
     */
    @Override
    public final void after() {
        log.debug("after {}", containerShortId);
        try {
            //only proceed with stopping docker resources if the container
            // has been started from this DockerRule context
            if (!containerStartedOutsideDockerRuleContext.get()) {
                dockerLogs.close();
                ContainerState state = dockerClient.inspectContainer(container.id()).state();
                log.debug("{} state {}", containerShortId, state);
                if (state.running()) {
                    dockerClient.stopContainer(container.id(), STOP_TIMEOUT);
                    log.info("{} stopped", containerShortId);
                }

                if (!builder.keepContainer()) {
                    dockerClient.removeContainer(container.id(), true);
                    log.info("{} deleted", containerShortId);
                    container = null;
                }
            }
        } catch (DockerException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Address of docker host. <b>Please note this is address of docker host as seen by docker client library
     * so it may not be valid docker host address in different contexts</b>.
     * <br/>
     * For example, if tests are run in unix-like environment with docker host on the same machine,
     * it will contain 'localhost' and will not point to docker host from inside container.
     * In such cases one should use {@link #getDockerContainerGateway()}.
     */
    public final String getDockerHost() {
        return dockerClient.getHost();
    }

    /**
     * Address of docker container gateway.
     */
    public final String getDockerContainerGateway() {
        return containerGateway;
    }

    /**
     * Address of docker container.
     */
    public String getContainerIp() {
        return containerIp;
    }

    /**
     * Get host dynamic port given container port was mapped to.
     *
     * @param containerPort Container port. Typically it matches Dockerfile EXPOSE directive.
     * @return Host port container port is exposed on.
     */
    public final String getExposedContainerPort(String containerPort) {
        String key = containerPort + DEFAULT_DOCKER_NET_PROTOCOL_TCP;
        List<PortBinding> list = containerPorts.get(key);
        if (list == null || list.size() == 0) {
            throw new IllegalStateException(String.format("%s is not exposed", key));
        }
        if (list.size() == 0) {
            throw new IllegalStateException(String.format("binding list for %s is empty", key));
        }

        if (list.size() > 1) {
            throw new IllegalStateException(String.format("binding list for %s is longer than 1", key));
        }
        return list.get(0).hostPort();
    }

    private void logNetworkSettings() {
        log.info("{} docker host: {}, ip: {}, gateway: {}, exposed ports: {}", containerShortId, dockerClient.getHost(),
                containerIp, containerGateway, containerPorts);
    }

    /**
     * Stop and wait till given string will show in container output.
     *
     * @param searchString String to wait for in container output.
     * @param waitTime     Wait time.
     * @throws TimeoutException On wait timeout.
     */
    public void waitFor(final String searchString, int waitTime) throws TimeoutException, InterruptedException {
        new WaitForUnit(TimeUnit.SECONDS, waitTime, TimeUnit.SECONDS, 1, new WaitForUnit.WaitForCondition() {
            @Override
            public boolean isConditionMet() {
                return StringUtils.contains(getLog(), searchString);
            }

            @Override
            public String tickMessage() {
                return String.format("wait for '%s' in log", searchString);
            }

            @Override
            public String timeoutMessage() {
                return String.format("container log: \n%s", getLog());
            }

        }) //
                .startWaiting();
    }

    /**
     * Block until container exit.
     */
    public void waitForExit() throws InterruptedException {
        try {
            dockerClient.waitContainer(container.id());
        } catch (DockerException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Container log.
     */
    public String getLog() {
        try (LogStream stream = dockerClient.logs(container.id(), LogsParam.stdout(), LogsParam.stderr());) {
            String fullLog = stream.readFully();
            if (log.isTraceEnabled()) {
                log.trace("{} full log: {}", containerShortId, StringUtils.replace(fullLog, "\n", "|"));
            }
            return fullLog;
        } catch (DockerException | InterruptedException e) {
            throw new IllegalStateException(e);
        }

    }

    /**
     * Id of container (null if it is not yet been created or has been stopped).
     */
    public String getContainerId() {
        return (container != null ? container.id() : null);
    }

    /**
     * {@link DockerClient} for direct container manipulation.
     */
    DockerClient getDockerClient() {
        return dockerClient;
    }

}

