#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *nums = malloc(5 * sizeof *nums);
    if (!nums) return 1;
    for (int i = 0; i < 5; i++) nums[i] = i * i;
    for (int i = 0; i < 5; i++) printf("%d squared is %d\n", i, nums[i]);
    free(nums);
    return 0;
}
