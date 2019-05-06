import React, { Component } from "react";
import { Link } from "react-router-dom";
import "./Home.css";

export default class Home extends Component {
  render() {
    return (
      <div className="Home">
        <div className="lander">
          <h1>Cidr House Rules</h1>
          <p>Read only interface into collected resources by Cidr House Rules</p>
        </div>
      </div>
    );
  }
}
