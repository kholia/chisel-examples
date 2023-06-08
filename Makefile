stuff:
	# DOCKER_BUILDKIT=1 docker build . -t base_image_stunnel:23.04 --no-cache -f base_image_stunnel.dockerfile --output "out"
	docker build . -t base_image_stunnel:22.04 --no-cache -f base_image_stunnel.dockerfile
	# DOCKER_BUILDKIT=1 docker build . -t base_image_busybox:23.04 --no-cache -f base_image_busybox.dockerfile --output "out"
	# docker build . -t base_image_busybox:23.04 -f base_image_busybox.dockerfile
	# docker build . -t base_image_busybox:23.04 --no-cache -f base_image_busybox.dockerfile
	# docker tag base_image_busybox:23.04 dhiru/base_image_busybox:23.04
	# docker tag base_image_busybox:23.04 docker.elastic.co/employees/kholia/base_image_busybox:23.04
	# docker tag base_image_stunnel:23.04 dhiru/base_image_stunnel:23.04
	# DOCKER_BUILDKIT=1 docker build . -t base_image_debug:22.04 --no-cache -f base_image_debug.dockerfile --output "out"
	# DOCKER_BUILDKIT=1 docker build . -t base_image_debug:22.04 -f base_image_debug.dockerfile --output "out"
	# DOCKER_BUILDKIT=1 docker build . -t base_image_debug:22.04 --no-cache -f base_image_debug.dockerfile --output "out"
	# DOCKER_BUILDKIT=1 docker build . -t base_image_debug:22.04 --no-cache -f base_image_debug.dockerfile
	# docker build . -t base_image_debug:22.04 --no-cache -f base_image_debug.dockerfile --output "out"
	# docker build . -t hello:22.04 -f hello.dockerfile
	# docker build . -t base_image:22.04 --no-cache -f base_image.dockerfile

	# docker build . -t base_image:22.04 -f base_image.dockerfile
	# docker build . -t base_image:22.04 --no-cache -f base_image.dockerfile
	# docker images | grep base_image

        # trivy image base_image:22.04

	# docker build . -t base_image_openssl:22.04 --no-cache -f base_image_openssl.dockerfile
	# docker images | grep base_image_openssl

	# docker build . -t base_image_java:22.04 -f base_image_jre8.dockerfile
