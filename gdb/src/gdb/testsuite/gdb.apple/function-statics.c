int foo() {
	static int bar = 3;
	static int bss_bar;
	bss_bar += 1;
	return bar + bss_bar + 2; // break here
}

int main() {
	foo();
	return foo();
}
