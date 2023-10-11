#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define max1 1000
#define max2 300

// ***************Functii pentru detectarea url-urilor malitioase *******************
int url_euristic_1(char *url, FILE *domains_in)
{
	char *domain = (char *)calloc(max1, sizeof(char));
	int ok = 0;
	while (fgets(domain, max1, domains_in)) {
		domain[strlen(domain) - 1] = '\0';
		if (strstr(url, domain)) {
			ok = 1;
			break;
		}
	}
	free(domain);
	rewind(domains_in);
	return ok;
}

int url_euristic_2(char *url)
{
	char *bad = ".exe";
	if (strstr(url, bad))
		return 1;
	return 0;
}

int nr_digits(char *url)
{
	char *numbers = "0123456789";
	int count = 0;
	for (int i = 0; i < strlen(numbers); i++) {
		if (strchr(url, numbers[i])) {
			char *p = strchr(url, numbers[i]);
			count++;
			while (p) {
				p = strchr(p + 1, numbers[i]);
				count++;
			}
		}
	}

	return count;
}

int url_euristic_3(char *url)
{
	char *domain = strtok(url, "/");
	if (nr_digits(domain) > (0.1 * strlen(domain)))
		return 1;
	return 0;
}

int url_euristic_4(char *url)
{
	char *domain = strtok(url, "/");
	if (strstr(domain, "www"))
		return 1;
	return 0;
}

// ***************Functii pentru detectarea traficului suspect *******************

int get_index_of_parameter(char *parametru, char *antet)
{
	char *p = strtok(antet, ",");
	int contor = 1;
	while (p) {
		if (strlen(p) < strlen(parametru)) {
			if (strstr(parametru, p))
				break;
		} else {
			if (strstr(p, parametru))
				break;
		}
		p = strtok(NULL, ",");
		contor++;
	}
	return contor;
}

int traffic_euristic_1(char *traffic, char *antet)
{
	char *parametru = "flow_duration";
	int contor = get_index_of_parameter(parametru, antet);

	char *flow_duration = strtok(traffic, ",");
	for (int i = 1; i < contor; i++)
		flow_duration = strtok(NULL, ",");

	int days = 0;
	if (sscanf(strtok(flow_duration, " :"), "%d", &days) == 1)
		; // do nothing

	strtok(NULL, " :"); // cuvantul "days"

	int h = 0;
	if (sscanf(strtok(NULL, " :"), "%d", &h) == 1) // ore
		; // do nothing

	int min = 0;
	if (sscanf(strtok(NULL, " :"), "%d", &min) == 1) // minute
		; // do nothing

	float sec = 0;
	if (sscanf(strtok(NULL, " :"), "%f", &sec) == 1) // secunde
		; // do nothing
	if (days > 0 || h > 0 || min > 0 || sec > 1)
		return 1;

	return 0;
}

int traffic_euristic_2(char *traffic, char *antet)
{
	char *parametru = "flow_pkts_payload.avg";
	int contor = get_index_of_parameter(parametru, antet);
	char *flow_pkts_payload = strtok(traffic, ",");

	for (int i = 1; i < contor; i++)
		flow_pkts_payload = strtok(NULL, ",");

	float value = 0;
	if (sscanf(flow_pkts_payload, "%f", &value) == 1)
		; // do nothing
	if (value != 0)
		return 1;
	return 0;
}

int main(void)
{
	// ***************Url malitios*******************
	char *file_urls = "./data/urls/urls.in";
	char *file_domains = "./data/urls/domains_database";

	FILE *url_in = fopen(file_urls, "r");
	FILE *url_out = fopen("urls-predictions.out", "w");
	FILE *domains_in = fopen(file_domains, "r");

	int url_e1 = 0, url_e2 = 0, url_e3 = 0, url_e4 = 0;
	int len = 0;

	char *url = (char *)calloc(max1, sizeof(char));

	while (fgets(url, max1, url_in)) {
		url_e1 = url_euristic_1(url, domains_in);
		url_e2 = url_euristic_2(url);
		url_e3 = url_euristic_3(url);
		url_e4 = url_euristic_4(url);
		if (url_e1 == 1 || url_e2 == 1 || url_e3 == 1 || url_e4 == 1)
			fprintf(url_out, "1\n");
		else
			fprintf(url_out, "0\n");
	}

	fclose(url_in); fclose(url_out); fclose(domains_in);
	free(url);

	// ***************Trafic malitios*******************
	char *file_traffics = "./data/traffic/traffic.in";

	FILE *traffic_in = fopen(file_traffics, "r");
	FILE *traffic_out = fopen("traffic-predictions.out", "w");

	int traffic_e1 = 0, traffic_e2 = 0;

	char *traffic = (char *)calloc(max2, sizeof(char));
	char *antet = (char *)calloc(max2, sizeof(char));
	char *aux1 = (char *)calloc(max2, sizeof(char));
	char *aux2 = (char *)calloc(max2, sizeof(char));

	fgets(antet, max2, traffic_in);

	while (fgets(traffic, max2, traffic_in)) {
		strcpy(aux1, traffic);
		strcpy(aux2, antet);
		traffic_e1 = traffic_euristic_1(aux1, aux2);
		strcpy(aux1, traffic);
		strcpy(aux2, antet);
		traffic_e2 = traffic_euristic_2(aux1, aux2);
		if (traffic_e1 == 1 && traffic_e2 == 1)
			fprintf(traffic_out, "1\n");
		else
			fprintf(traffic_out, "0\n");
	}

	fclose(traffic_in); fclose(traffic_out);
	free(traffic);
	free(antet);
	free(aux1);
	free(aux2);
	return 0;
}
