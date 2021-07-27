from requests_html import HTMLSession
from tabulate import tabulate
import sys

def main(vector):

	metrics = {
		"AV": {
			"N": "Rede",
			"A": "Adjacente",
			"L": "Local",
			"P": "Físico"
		},
		"AC": {
			"L": "Baixo",
			"H": "Alto"
		},
		"PR": {
			"N": "Nenhum",
			"L": "Baixo",
			"H": "Alto"
		},
		"UI": {
			"N": "Nenhum",
			"R": "Requerido"
		},
		"S": {
			"U": "Inalterado",
			"C": "Alterado"
		},
		"C": {
			"N": "Nenhum",
			"L": "Baixo",
			"H": "Alto"
		},
		"I": {
			"N": "Nenhum",
			"L": "Baixo",
			"H": "Alto"
		},
		"A": {
			"N": "Nenhum",
			"L": "Baixo",
			"H": "Alto"
		},	
	}

	url = "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector={vector}&version=3.1".format(vector=vector)

	session = HTMLSession()
	r = session.get(url)
	r.html.render()

	print()

	tabela = []
	header = ["Indicador", "Métrica"]

	for metric in vector.split("/"):
		v = metric.split(":")
		if v[0] == "AV":
			tabela.append(["Vetor de Acesso:", metrics[v[0]][v[1]]])
		if v[0] == "AC":
			tabela.append(["Complexidade do Ataque:", metrics[v[0]][v[1]]])
		if v[0] == "PR":
			tabela.append(["Privilégios exigidos:", metrics[v[0]][v[1]]])
		if v[0] == "UI":
			tabela.append(["Interação do usuário:", metrics[v[0]][v[1]]])
		if v[0] == "S":
			tabela.append(["Escopo:", metrics[v[0]][v[1]]])
		if v[0] == "C":
			tabela.append(["Impacto de Confidencialidade:", metrics[v[0]][v[1]]])
		if v[0] == "I":
			tabela.append(["Impacto de Integridade:", metrics[v[0]][v[1]]])
		if v[0] == "A":
			tabela.append(["Impacto de Disponibilidade:", metrics[v[0]][v[1]]])

	base_score = r.html.find("#cvss-base-score-cell")
	impact_score = r.html.find("#cvss-impact-score-cell")
	exploitability_score = r.html.find("#cvss-exploitability-score-cell")

	tabela.append(["", ""])
	tabela.append(["Explorabilidade:",exploitability_score[0].text])
	tabela.append(["Impacto:",impact_score[0].text])
	tabela.append(["CVSS Base:",base_score[0].text])

	print(tabulate(tabela, headers=header, tablefmt="psql"))

if __name__ == '__main__':
	
	if len(sys.argv) == 2:
	    main(sys.argv[1])
	else:
		print("Modo de uso: \t", sys.argv[0], "CVSS-Vector")
		print("Exemplo: \t", sys.argv[0], "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L")
