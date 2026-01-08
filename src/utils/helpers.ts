export const beautify = (str: string, n = 2) => {
    if (!str) return str;
    return `${str.slice(0, n)}...${str.slice(-n)}`;
};