struct bpf_pinned_map {
	const char *name;
	const char *filename;
	int map_fd;
};