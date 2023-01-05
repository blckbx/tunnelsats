import React from "react";
import { Alert, Row, Col } from "react-bootstrap";
import { SiTorproject } from "react-icons/si";
import { TbSum } from "react-icons/tb";
import { IoGitNetworkSharp } from "react-icons/io5";
import { FaNetworkWired } from "react-icons/fa";
import CountUp from "react-countup";

const HeaderInfo = (props) => {
  return (
    <div>
      <Alert variant="secondary">
        {/* <Alert.Heading>How it works:</Alert.Heading> */}
        <p>
          Tunnel⚡️Sats provides scripts for lightning nodes enabling hybrid
          mode (Clearnet & Tor) and offers paid VPN servers on various
          continents for fixed terms. Our secured and LN-only configured VPNs
          support port-forwarding to connect with other lightning nodes.
        </p>
        <p>
          <b className="price">How Tunnel⚡️Sats works</b>
          <br></br>Select a preferred region, timeframe and pay the invoice via
          lightning to receive a WireGuard configuration file. Please follow the
          detailed installation instructions described on the TunnelSats{" "}
          <a
            href="https://tunnelsats.github.io/tunnelsats/"
            target="_blank"
            rel="noreferrer"
          >
            guide
          </a>{" "}
          and{" "}
          <a
            href="https://tunnelsats.github.io/tunnelsats/FAQ.html"
            target="_blank"
            rel="noreferrer"
          >
            faq
          </a>{" "}
          pages.
        </p>
        <hr />
        <p className="price">
          <strong>Lightning Node Statistics</strong>
        </p>
        <Row>
          <Col>
            <TbSum size={20} title="total" />{" "}
            <CountUp end={props.stats[0]} duration={4.0} className="price" />
          </Col>
          <Col>
            <FaNetworkWired size={20} title="clearnet" />{"  "}
            <CountUp end={props.stats[1]} duration={3.0} className="price" />
          </Col>
          <Col>
            <IoGitNetworkSharp size={20} title="hybrid" />{" "}
            <CountUp end={props.stats[2]} duration={2.5} className="price" />
          </Col>
          <Col>
            <SiTorproject size={20} title="Tor" />{" "}
            <CountUp end={props.stats[3]} duration={3.5} className="price" />
          </Col>
        </Row>
      </Alert>
    </div>
  );
};

export default HeaderInfo;
